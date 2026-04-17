// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Enum representing various provisioning errors that can occur during provisioning operations.
 *
 * <p>These error codes are used in the {@link IProvisioningCallback#onError} callback
 * to indicate the specific type of error that occurred during a provisioning operation.
 */
package android.system.virtualization.payload;

enum ProvisioningError {
    /** The provided argument is invalid. */
    INVALID_ARGUMENT = 1,

    /** Permission to perform the operation is denied. */
    PERMISSION_DENIED = 2,

    /** A system error occurred during the operation. */
    SYSTEM_ERROR = 3,

    /** Encrypted store is not enabled for the VM. */
    ENCRYPTEDSTORE_IS_NOT_ENABLED = 4,

    /** A network error occurred during provisioning. */
    NETWORK_ERROR = 5,

    /** An unknown error occurred. */
    UNKNOWN_ERROR = 6,

    // TODO Add more error codes as needed
}
