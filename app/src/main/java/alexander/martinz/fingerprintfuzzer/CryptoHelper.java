/*
 * Copyright 2016 Alexander Martinz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package alexander.martinz.fingerprintfuzzer;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public class CryptoHelper {
    private static final String TAG = CryptoHelper.class.getSimpleName();
    private static final boolean DEBUG = true;

    private static final String DEFAULT_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String DEFAULT_BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;
    private static final String DEFAULT_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7;

    private static final String KEY_STORE_ANDROID = "AndroidKeyStore";
    private static final String KEY_NAME_DEFAULT = "fingerprint_fuzzer";
    private static final int KEY_SIZE_DEFAULT = 256;

    private final String keyName;

    private KeyStore keyStore;

    /* package */ CryptoHelper(@NonNull Context context, @Nullable String keyName) {
        if (TextUtils.isEmpty(keyName)) {
            this.keyName = String.format("%s.%s", context.getPackageName(), KEY_NAME_DEFAULT);
        } else {
            this.keyName = keyName;
        }
    }

    @Nullable /* package */ KeyStore loadKeyStore() {
        if (keyStore == null) {
            try {
                keyStore = KeyStore.getInstance(KEY_STORE_ANDROID);
                keyStore.load(null);
            } catch (Exception exc) {
                if (DEBUG) {
                    Log.e(TAG, "Could not load key store!");
                }
            }
        }
        return keyStore;
    }

    @Nullable /* package */ Cipher initCipherDecryption(@NonNull byte[] iv) {
        return initCipher(Cipher.DECRYPT_MODE, new IvParameterSpec(iv));
    }

    @Nullable /* package */ Cipher initCipherEncryption() {
        return initCipher(Cipher.ENCRYPT_MODE, null);
    }

    @Nullable private Cipher initCipher(int opmode, @Nullable IvParameterSpec ivParameterSpec) {
        final Cipher cipher = createCipher();
        if (cipher == null) {
            return null;
        }

        final SecretKey secretKey = getOrCreateKey();
        if (secretKey == null) {
            return null;
        }

        try {
            if (ivParameterSpec != null) {
                cipher.init(opmode, secretKey, ivParameterSpec);
            } else {
                cipher.init(opmode, secretKey);
            }
        } catch (KeyPermanentlyInvalidatedException exc) {
            if (DEBUG) {
                Log.e(TAG, "Could not init cipher, because key is permanently invalidated", exc);
            }
            return null;
        } catch (InvalidAlgorithmParameterException | InvalidKeyException ike) {
            if (DEBUG) {
                Log.e(TAG, "Could not init cipher", ike);
            }
            return null;
        }

        return cipher;
    }

    @Nullable private Cipher createCipher() {
        try {
            return Cipher.getInstance(String.format("%s/%s/%s", DEFAULT_ALGORITHM, DEFAULT_BLOCK_MODE, DEFAULT_PADDING));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exc) {
            if (DEBUG) {
                Log.e(TAG, "Could not create cipher", exc);
            }
        }
        return null;
    }

    @Nullable private SecretKey getOrCreateKey() {
        final KeyStore keyStore = loadKeyStore();
        if (keyStore == null) {
            return null;
        }

        SecretKey secretKey = getKey(keyStore);
        if (secretKey == null) {
            secretKey = createKey();
        }
        return secretKey;
    }

    @Nullable private SecretKey getKey(KeyStore keyStore) {
        try {
            return (SecretKey) keyStore.getKey(keyName, null);
        } catch (Exception exc) {
            if (DEBUG) {
                Log.e(TAG, "Could not get key from key store", exc);
            }
        }
        return null;
    }

    @Nullable private SecretKey createKey() {
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance(DEFAULT_ALGORITHM, KEY_STORE_ANDROID);
            keyGen.init(new KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(DEFAULT_BLOCK_MODE)
                    .setEncryptionPaddings(DEFAULT_PADDING)
                    .setKeySize(KEY_SIZE_DEFAULT)
                    .setUserAuthenticationRequired(true)
                    .build());
            return keyGen.generateKey();
        } catch (Exception exc) {
            if (DEBUG) {
                Log.e(TAG, "Could not create key", exc);
            }
        }
        return null;
    }

}
