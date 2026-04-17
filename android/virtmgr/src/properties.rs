// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rustutils::system_properties;

fn get_kvmtool_property() -> bool {
    system_properties::read_bool("persist.avf.kvmtool", false)
        .unwrap_or(false)
}

pub fn use_kvmtool() -> bool {
    if get_kvmtool_property() {
        return true;
    }

    let use_kvmtool = std::fs::exists("/data/use_kvmtool");
    use_kvmtool.is_ok() && use_kvmtool.unwrap()
}

fn get_realm_property() -> bool {
    system_properties::read_bool("persist.avf.realm", false)
        .unwrap_or(false)
}

pub fn use_realm() -> bool {
    if get_realm_property() {
        return true;
    }

    let ret = std::fs::exists("/data/use_realm");
    ret.is_ok() && ret.unwrap()
}
