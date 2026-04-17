// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Interface for provisioning callback notifications.
 *
 * <p>This interface provides callbacks for monitoring the status of provisioning operations.
 * Implement this interface to receive notifications about the success or failure of
 * provisioning operations initiated through {@link Cca#startProvisioning}.
 */
package android.system.virtualization.payload;

import android.system.virtualization.payload.ProvisioningError;

interface IProvisioningCallback {
    /**
     * Called when an error occurs during the provisioning operation.
     *
     * @param error {@link android.system.virtualization.payload.ProvisioningError} The type of error that occurred during provisioning.
     */
    void onError(ProvisioningError error);

    /**
     * Called when the provisioning operation completes successfully.
     *
     * @param url The URL of the provisioned resource.
     * @param destination The destination path where the resource was stored.
     */
    void onSuccess(String url, String destination);
}
