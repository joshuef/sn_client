// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{AccessContainerEntry, AuthError, AuthFuture, Authenticator};
use access_container;
use app_auth::{self, AppState, app_state};
use config;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, ReprC, StringError, base64_encode,
                catch_unwind_cb, from_c_str};
use futures::{Future, Stream, stream};
use futures::future::{self, Either};
use maidsafe_utilities::serialisation::deserialise;
use revocation::{flush_app_revocation_queue, revoke_app};
use routing::{ClientError, User, XorName};
use rust_sodium::crypto::sign;
use safe_core::{Client, CoreError, FutureExt, recovery};
use safe_core::ipc::{self, IpcError, IpcMsg, decode_msg};
use safe_core::ipc::req::{AuthReq, ContainerPermissions, ContainersReq, IpcReq, ShareMDataReq,
                          container_perms_into_permission_set};
use safe_core::ipc::req::ffi::{AuthReq as FfiAuthReq, ContainersReq as FfiContainersReq,
                               ShareMDataReq as FfiShareMDataReq};
use safe_core::ipc::resp::{IpcResp, METADATA_KEY, UserMetadata};
use safe_core::ipc::resp::ffi::MetadataResponse as FfiUserMetadata;
use safe_core::ipc::resp::ffi::MetadataResponse;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

/// Decodes a given encoded IPC message and returns either an `IpcMsg` struct or
/// an error code + description & an encoded `IpcMsg::Resp` in case of an error
#[cfg_attr(feature = "cargo-clippy", allow(type_complexity))]
pub fn decode_ipc_msg(
    client: &Client<()>,
    msg: IpcMsg,
) -> Box<AuthFuture<Result<IpcMsg, (i32, CString, CString)>>> {
    match msg {
        IpcMsg::Req {
            req: IpcReq::Auth(auth_req),
            req_id,
        } => {
            // Ok status should be returned for all app states (including
            // Revoked and Authenticated).
            ok!(Ok(IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Auth(auth_req),
            }))
        }
        IpcMsg::Req {
            req: IpcReq::Unregistered,
            req_id,
        } => {
            ok!(Ok(IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Unregistered,
            }))
        }
        IpcMsg::Req {
            req: IpcReq::ShareMData(share_mdata_req),
            req_id,
        } => {
            ok!(Ok(IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::ShareMData(share_mdata_req),
            }))
        }
        IpcMsg::Req {
            req: IpcReq::Containers(cont_req),
            req_id,
        } => {
            let app_id = cont_req.app.id.clone();
            let app_id2 = app_id.clone();

            let c2 = client.clone();

            config::list_apps(client)
                .and_then(move |(_config_version, config)| {
                    app_state(&c2, &config, &app_id)
                })
                .and_then(move |app_state| {
                    match app_state {
                        AppState::Authenticated => {
                            Ok(Ok(IpcMsg::Req {
                                req_id: req_id,
                                req: IpcReq::Containers(cont_req),
                            }))
                        }
                        AppState::Revoked |
                        AppState::NotAuthenticated => {
                            // App is not authenticated
                            let (error_code, description) =
                                ffi_error!(AuthError::from(IpcError::UnknownApp));

                            let resp = IpcMsg::Resp {
                                resp: IpcResp::Auth(Err(IpcError::UnknownApp)),
                                req_id: req_id,
                            };
                            let resp = encode_response(&resp, &app_id2)?;

                            Ok(Err((error_code, description, resp)))
                        }
                    }
                })
                .into_box()
        }
        IpcMsg::Resp { .. } |
        IpcMsg::Revoked { .. } |
        IpcMsg::Err(..) => {
            return err!(AuthError::IpcError(IpcError::InvalidMsg.into()));
        }
    }
}

/// Decodes a given encoded IPC message without requiring an authorised account
#[no_mangle]
pub unsafe extern "C" fn auth_unregistered_decode_ipc_msg(
    msg: *const c_char,
    user_data: *mut c_void,
    o_unregistered: extern "C" fn(*mut c_void, u32),
    o_err: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        match msg {
            IpcMsg::Req {
                req: IpcReq::Unregistered,
                req_id,
            } => {
                o_unregistered(user_data.0, req_id);
            }
            _ => {
                call_result_cb!(
                    Err::<(), _>(AuthError::CoreError(CoreError::OperationForbidden)),
                    user_data,
                    o_err
                );
            }
        }

        Ok(())
    })
}

/// Decodes a given encoded IPC message and calls a corresponding callback
#[no_mangle]
pub unsafe extern "C" fn auth_decode_ipc_msg(
    auth: *const Authenticator,
    msg: *const c_char,
    user_data: *mut c_void,
    o_auth: extern "C" fn(*mut c_void, u32, *const FfiAuthReq),
    o_containers: extern "C" fn(*mut c_void, u32, *const FfiContainersReq),
    o_unregistered: extern "C" fn(*mut c_void, u32),
    o_share_mdata: extern "C" fn(*mut c_void,
                                 u32,
                                 *const FfiShareMDataReq,
                                 *const FfiUserMetadata),
    o_err: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        (*auth).send(move |client| {
            let c1 = client.clone();
            decode_ipc_msg(client, msg)
                .and_then(move |msg| match msg {
                    Ok(IpcMsg::Req {
                           req: IpcReq::Auth(auth_req),
                           req_id,
                       }) => {
                        let repr_c = fry!(auth_req.into_repr_c().map_err(AuthError::IpcError));
                        o_auth(user_data.0, req_id, &repr_c);
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                           req: IpcReq::Containers(cont_req),
                           req_id,
                       }) => {
                        let repr_c = fry!(cont_req.into_repr_c().map_err(AuthError::IpcError));
                        o_containers(user_data.0, req_id, &repr_c);
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                           req: IpcReq::Unregistered,
                           req_id,
                       }) => {
                        o_unregistered(user_data.0, req_id);
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                           req: IpcReq::ShareMData(share_mdata_req),
                           req_id,
                       }) => {
                        decode_share_mdata_req(&c1, &share_mdata_req)
                            .and_then(move |metadatas| {
                                let share_mdata_req_repr_c = share_mdata_req.into_repr_c()?;

                                let mut ffi_metadatas = Vec::with_capacity(metadatas.len());
                                for metadata in metadatas {
                                    if let Some(metadata) = metadata {
                                        ffi_metadatas.push(metadata);
                                    } else {
                                        ffi_metadatas.push(FfiUserMetadata::invalid());
                                    }
                                }

                                o_share_mdata(
                                    user_data.0,
                                    req_id,
                                    &share_mdata_req_repr_c,
                                    ffi_metadatas.as_ptr(),
                                );

                                Ok(())
                            })
                            .into_box()
                    }
                    Err((error_code, description, err)) => {
                        o_err(
                            user_data.0,
                            FfiResult {
                                error_code,
                                description: description.as_ptr(),
                            },
                            err.as_ptr(),
                        );
                        ok!(())
                    }
                    Ok(IpcMsg::Resp { .. }) |
                    Ok(IpcMsg::Revoked { .. }) |
                    Ok(IpcMsg::Err(..)) => {
                        let err = AuthError::Unexpected(
                            "Unexpected msg \
                                                               type"
                                .to_owned(),
                        );
                        call_result_cb!(Err::<(), _>(err), user_data, o_err);
                        ok!(())
                    }
                })
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_err);
                })
                .into_box()
                .into()
        })?;
        Ok(())
    })
}

/// Encode share mutable data response.
#[no_mangle]
pub unsafe extern "C" fn encode_share_mdata_resp(
    auth: *const Authenticator,
    req: *const FfiShareMDataReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let share_mdata_req = ShareMDataReq::clone_from_repr_c(req)?;
        if is_granted {
            (*auth).send(move |client| {
                let client_cloned0 = client.clone();
                let client_cloned1 = client.clone();
                let user_data = user_data.0;
                config::get_app(client, &share_mdata_req.app.id)
                    .and_then(move |app_info| {
                        let app_id = share_mdata_req.app.id;
                        let user = User::Key(app_info.keys.sign_pk);
                        let num_mdatas = share_mdata_req.mdata.len();
                        stream::iter(share_mdata_req.mdata.into_iter().map(Ok))
                        .map(move |mdata| {
                            client_cloned0.get_mdata_shell(mdata.name, mdata.type_tag)
                                          .map(|md| (md.version(), mdata))
                        })
                        .buffer_unordered(num_mdatas)
                        .map(move |(version, mdata)| {
                            client_cloned1.set_mdata_user_permissions(
                                mdata.name,
                                mdata.type_tag,
                                user,
                                mdata.perms,
                                version + 1,
                            )
                        })
                        .buffer_unordered(num_mdatas)
                        .map_err(AuthError::CoreError)
                        .for_each(|()| Ok(()))
                        .and_then(move |()| {
                            let resp = encode_response(
                                &IpcMsg::Resp {
                                    req_id: req_id,
                                    resp: IpcResp::ShareMData(Ok(())),
                                },
                                &app_id
                            ).map_err(AuthError::IpcError)?;
                            o_cb(
                                user_data,
                                FFI_RESULT_OK,
                                resp.as_ptr()
                            );
                            Ok(())
                        })
                        .into_box()
                    })
                    .map_err(move |e| {
                        call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                    })
                    .into_box()
                    .into()
            })?;
        } else {
            let resp = encode_response(
                &IpcMsg::Resp {
                    req_id: req_id,
                    resp: IpcResp::ShareMData(Err(IpcError::ShareMDataDenied)),
                },
                &share_mdata_req.app.id,
            )?;
            let (error_code, description) = ffi_error!(AuthError::from(IpcError::ShareMDataDenied));
            o_cb(
                user_data.0,
                FfiResult {
                    error_code,
                    description: description.as_ptr(),
                },
                resp.as_ptr(),
            );
        }
        Ok(())
    })
}

/// Revoke app access
#[no_mangle]
pub unsafe extern "C" fn auth_revoke_app(
    auth: *const Authenticator,
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        let app_id = from_c_str(app_id)?;

        (*auth).send(move |client| {
            revoke_app(client, &app_id)
                .and_then(move |_| {
                    let resp =
                        encode_response(&IpcMsg::Revoked { app_id: app_id.clone() }, &app_id)?;
                    o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    });
}

/// Flush the revocation queue.
#[no_mangle]
pub unsafe extern "C" fn auth_flush_app_revocation_queue(
    auth: *const Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
            flush_app_revocation_queue(client)
                .then(move |res| {
                    call_result_cb!(res, user_data, o_cb);
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Encodes a response to unregistered client authentication request
#[no_mangle]
pub unsafe extern "C" fn encode_unregistered_resp(
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        if !is_granted {
            let resp = encode_response(
                &IpcMsg::Resp {
                    req_id: req_id,
                    resp: IpcResp::Unregistered(Err(IpcError::AuthDenied)),
                },
                "unregistered",
            )?;

            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(
                user_data.0,
                FfiResult {
                    error_code,
                    description: description.as_ptr(),
                },
                resp.as_ptr(),
            );
        } else {
            let bootstrap_cfg = Client::<()>::bootstrap_config()?;

            let resp = encode_response(
                &IpcMsg::Resp {
                    req_id: req_id,
                    resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
                },
                "unregistered",
            )?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        }
        Ok(())
    })
}

/// Provides and encodes an Authenticator response
#[no_mangle]
pub unsafe extern "C" fn encode_auth_resp(
    auth: *const Authenticator,
    req: *const FfiAuthReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let auth_req = AuthReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(
                &IpcMsg::Resp {
                    req_id: req_id,
                    resp: IpcResp::Auth(Err(IpcError::AuthDenied)),
                },
                &auth_req.app.id,
            )?;

            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(
                user_data.0,
                FfiResult {
                    error_code,
                    description: description.as_ptr(),
                },
                resp.as_ptr(),
            );
        } else {
            let app_id = auth_req.app.id.clone();
            let app_id2 = app_id.clone();

            (*auth).send(move |client| {
                app_auth::authenticate(client, auth_req)
                    .and_then(move |auth_granted| {
                        let resp = encode_response(
                            &IpcMsg::Resp {
                                req_id: req_id,
                                resp: IpcResp::Auth(Ok(auth_granted)),
                            },
                            &app_id,
                        )?;

                        Ok(o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr()))
                    })
                    .or_else(move |e| -> Result<(), AuthError> {
                        let (error_code, description) = ffi_error!(e);
                        let resp = encode_response(
                            &IpcMsg::Resp {
                                req_id: req_id,
                                resp: IpcResp::Auth(Err(e.into())),
                            },
                            &app_id2,
                        )?;
                        Ok(o_cb(
                            user_data.0,
                            FfiResult {
                                error_code,
                                description: description.as_ptr(),
                            },
                            resp.as_ptr(),
                        ))
                    })
                    .map_err(move |e| {
                        call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                    })
                    .into_box()
                    .into()
            })?;
        }

        Ok(())
    })
}

/// Update containers permissions for an App
#[no_mangle]
pub unsafe extern "C" fn encode_containers_resp(
    auth: *const Authenticator,
    req: *const FfiContainersReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let cont_req = ContainersReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(
                &IpcMsg::Resp {
                    req_id: req_id,
                    resp: IpcResp::Containers(Err(IpcError::AuthDenied)),
                },
                &cont_req.app.id,
            )?;
            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(
                user_data.0,
                FfiResult {
                    error_code,
                    description: description.as_ptr(),
                },
                resp.as_ptr(),
            );
        } else {
            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id.clone();
            let app_id2 = app_id.clone();

            (*auth).send(move |client| {
                let c2 = client.clone();
                let c3 = client.clone();
                let c4 = client.clone();

                config::get_app(client, &app_id)
                    .and_then(move |app| {
                        let sign_pk = app.keys.sign_pk;
                        update_container_perms(&c2, permissions, sign_pk).map(
                            move |perms| (app, perms),
                        )
                    })
                    .and_then(move |(app, mut perms)| {
                        let app_keys = app.keys;

                        access_container::fetch_entry(&c3, &app_id, app_keys.clone())
                            .then(move |res| {
                                let version = match res {
                                    // Updating an existing entry
                                    Ok((version, Some(mut existing_perms))) => {
                                        for (key, val) in perms {
                                            let _ = existing_perms.insert(key, val);
                                        }
                                        perms = existing_perms;

                                        version + 1
                                    }

                                    // Adding a new access container entry
                                    Ok((_, None)) |
                                        Err(AuthError::CoreError(
                                        CoreError::RoutingClientError(
                                            ClientError::NoSuchEntry))) => 0,

                                    // Error has occurred while trying to get an
                                    // existing entry
                                    Err(e) => return Err(e),
                                };
                                Ok((version, app_id, app_keys, perms))
                            })
                    })
                    .and_then(move |(version, app_id, app_keys, perms)| {
                        access_container::put_entry(&c4, &app_id, &app_keys, &perms, version)
                    })
                    .and_then(move |_| {
                        let resp = encode_response(
                            &IpcMsg::Resp {
                                req_id: req_id,
                                resp: IpcResp::Containers(Ok(())),
                            },
                            &cont_req.app.id,
                        )?;
                        o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                        Ok(())
                    })
                    .or_else(move |e| -> Result<(), AuthError> {
                        let (error_code, description) = ffi_error!(e);
                        let resp = encode_response(
                            &IpcMsg::Resp {
                                req_id: req_id,
                                resp: IpcResp::Containers(Err(e.into())),
                            },
                            &app_id2,
                        )?;
                        Ok(o_cb(
                            user_data.0,
                            FfiResult {
                                error_code,
                                description: description.as_ptr(),
                            },
                            resp.as_ptr(),
                        ))
                    })
                    .map_err(move |e| debug!("Unexpected error: {:?}", e))
                    .into_box()
                    .into()
            })?;
        }

        Ok(())
    });
}

/// Updates containers permissions (adds a given key to the permissions set)
pub fn update_container_perms(
    client: &Client<()>,
    permissions: HashMap<String, ContainerPermissions>,
    sign_pk: sign::PublicKey,
) -> Box<AuthFuture<AccessContainerEntry>> {
    let c2 = client.clone();

    access_container::authenticator_entry(client)
        .and_then(move |(_, mut root_containers)| {
            let mut reqs = Vec::new();
            let client = c2.clone();

            for (container_key, access) in permissions {
                let c2 = client.clone();
                let mdata_info = fry!(root_containers.remove(&container_key).ok_or_else(|| {
                    AuthError::from(format!(
                        "'{}' not found in the access container",
                        container_key
                    ))
                }));
                let perm_set = container_perms_into_permission_set(&access);

                let fut = client
                    .get_mdata_version(mdata_info.name, mdata_info.type_tag)
                    .and_then(move |version| {
                        recovery::set_mdata_user_permissions(
                            &c2,
                            mdata_info.name,
                            mdata_info.type_tag,
                            User::Key(sign_pk),
                            perm_set,
                            version + 1,
                        ).map(move |_| (container_key, mdata_info, access))
                    })
                    .map_err(AuthError::from);

                reqs.push(fut);
            }

            future::join_all(reqs).into_box()
        })
        .map(|perms| {
            perms
                .into_iter()
                .map(|(container_key, dir, access)| {
                    (container_key, (dir, access))
                })
                .collect()
        })
        .map_err(AuthError::from)
        .into_box()
}

fn encode_response(msg: &IpcMsg, app_id: &str) -> Result<CString, IpcError> {
    let app_id = base64_encode(app_id.as_bytes());
    let resp = ipc::encode_msg(msg, &format!("safe-{}", app_id))?;
    Ok(CString::new(resp).map_err(StringError::from)?)
}

enum ShareMDataError {
    InvalidOwner(XorName, u64),
    InvalidMetadata,
}

fn decode_share_mdata_req(
    client: &Client<()>,
    req: &ShareMDataReq,
) -> Box<AuthFuture<Vec<Option<MetadataResponse>>>> {
    let user = fry!(client.public_signing_key());
    let num_mdatas = req.mdata.len();
    let mut futures = Vec::with_capacity(num_mdatas);

    for mdata in &req.mdata {
        let client = client.clone();
        let name = mdata.name;
        let type_tag = mdata.type_tag;

        let future = client
            .get_mdata_shell(name, type_tag)
            .and_then(move |shell| if shell.owners().contains(&user) {
                let future_metadata = client
                    .get_mdata_value(name, type_tag, METADATA_KEY.into())
                    .then(move |res| match res {
                        Ok(value) => Ok(
                            deserialise::<UserMetadata>(&value.content)
                            .map_err(|_| { ShareMDataError::InvalidMetadata })
                            .and_then(move |metadata| {
                                match metadata.into_md_response(name, type_tag) {
                                    Ok(meta) => Ok(meta),
                                    Err(_) => Err(ShareMDataError::InvalidMetadata)
                                }
                            }) )
                        ,
                        Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) =>
                            // Allow requesting shared access to arbitrary Mutable Data objects even
                            // if they don't have metadata.
                                Ok( UserMetadata {
                                    name: None,
                                    description: None,
                                }.into_md_response(name, type_tag)
                               .map_err(|_| {
                                   ShareMDataError::InvalidMetadata
                               })),
                        Err(error) => Err(error),
                    });
                Either::A(future_metadata)
            } else {
                Either::B(future::ok(
                    Err(ShareMDataError::InvalidOwner(name, type_tag)),
                ))
            })
            .map_err(AuthError::from);

        futures.push(future);
    }

    future::join_all(futures)
        .and_then(move |results| {
            let mut metadatas = Vec::with_capacity(num_mdatas);
            let mut invalids = Vec::with_capacity(num_mdatas);

            for result in results {
                match result {
                    Ok(metadata) => metadatas.push(Some(metadata)),
                    Err(ShareMDataError::InvalidMetadata) => metadatas.push(None),
                    Err(ShareMDataError::InvalidOwner(name, type_tag)) => {
                        invalids.push((name, type_tag))
                    }
                }
            }

            if invalids.is_empty() {
                Ok(metadatas)
            } else {
                Err(AuthError::IpcError(IpcError::InvalidOwner(invalids)))
            }
        })
        .into_box()
}