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
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.os.CancellationSignal;
import android.util.Log;

import javax.crypto.Cipher;

@TargetApi(Build.VERSION_CODES.M)
public class FingerPrinter {
    private static final String TAG = FingerPrinter.class.getSimpleName();

    public static final int SETUP_OK = 0;
    public static final int SETUP_NO_HARDWARE = 1;
    public static final int SETUP_NO_SECURE_LOCK_SCREEN = 2;
    public static final int SETUP_NO_FINGERPRINTS = 3;

    public final Context context;
    private final CryptoHelper cryptoHelper;

    private final KeyguardManager keyguardManager;
    private final FingerprintManagerCompat fingerprintManager;
    private final FingerprinterCallback authenticationCallback;

    private Cipher cipherEnc;
    private FingerprintManagerCompat.CryptoObject cryptoObjectEnc;

    private CancellationSignal cancellationSignal;

    private boolean selfCanceled;

    public static class FingerprinterCallback extends FingerprintManagerCompat.AuthenticationCallback { }

    public FingerPrinter(@NonNull Context context, FingerprinterCallback authenticationCallback) {
        this(context, authenticationCallback, null);
    }

    public FingerPrinter(@NonNull Context context, FingerprinterCallback authenticationCallback, @Nullable String keyName) {
        this.context = context;
        this.cryptoHelper = new CryptoHelper(context, keyName);

        this.keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        this.fingerprintManager = FingerprintManagerCompat.from(context);

        this.authenticationCallback = authenticationCallback;
    }

    public boolean init() {
        if (cipherEnc == null) {
            cipherEnc = cryptoHelper.initCipherEncryption();
        }
        if (cipherEnc == null) {
            return false;
        }
        if (cryptoObjectEnc == null) {
            cryptoObjectEnc = new FingerprintManagerCompat.CryptoObject(cipherEnc);
        }

        return true;
    }

    public void onDestroy() {
        stopListening();
    }

    public int hasFingerprintsSetup() {
        if (!fingerprintManager.isHardwareDetected()) {
            Log.d(TAG, "No fingerprint hardware detected!");
            return SETUP_NO_HARDWARE;
        }
        if (!keyguardManager.isKeyguardSecure()) {
            Log.d(TAG, "No secure lock screen set up!");
            return SETUP_NO_SECURE_LOCK_SCREEN;
        }
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Log.d(TAG, "User did not setup fingerprints!");
            return SETUP_NO_FINGERPRINTS;
        }
        return SETUP_OK;
    }

    public void startListening() {
        if (hasFingerprintsSetup() != SETUP_OK) {
            return;
        }

        cancellationSignal = new CancellationSignal();
        selfCanceled = false;
        fingerprintManager.authenticate(cryptoObjectEnc, 0 /* flags */, cancellationSignal, fingerprinterCallback, null);
    }

    public void stopListening() {
        if (cancellationSignal != null) {
            selfCanceled = true;
            cancellationSignal.cancel();
            cancellationSignal = null;
        }
    }

    public Cipher getCipherEnc() {
        return cipherEnc;
    }

    private final FingerprinterCallback fingerprinterCallback = new FingerprinterCallback() {
        @Override public void onAuthenticationError(int errMsgId, CharSequence errString) {
            if (!selfCanceled) {
                if (authenticationCallback != null) {
                    authenticationCallback.onAuthenticationError(errMsgId, errString);
                }
            }
        }

        @Override public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            if (authenticationCallback != null) {
                authenticationCallback.onAuthenticationHelp(helpMsgId, helpString);
            }
        }

        @Override public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            if (authenticationCallback != null) {
                authenticationCallback.onAuthenticationSucceeded(result);
            }
        }

        @Override public void onAuthenticationFailed() {
            if (authenticationCallback != null) {
                authenticationCallback.onAuthenticationFailed();
            }
        }
    };

}
