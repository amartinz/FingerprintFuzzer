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

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    private FingerPrinter fingerPrinter;

    private int counter;
    private boolean isRunning;
    private boolean isSetup;

    private FuzzerTask fuzzerTask;
    private boolean isFuzzing;

    private TextView textStatus;
    private TextView textCounter;
    private Button btnStartStop;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fingerPrinter = new FingerPrinter(getApplicationContext(), callback);
        counter = 0;

        textStatus = (TextView) findViewById(R.id.status);
        textCounter = (TextView) findViewById(R.id.counter);
        btnStartStop = (Button) findViewById(R.id.start_stop);

        textCounter.setText(getString(R.string.counter_message, counter));
        btnStartStop.setEnabled(false);
        btnStartStop.setText(R.string.start);
        btnStartStop.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (isRunning) {
                    isRunning = false;
                    stop();
                    btnStartStop.setText(R.string.start);

                    if (isFuzzing) {
                        stopFuzzing();
                    }
                } else {
                    isRunning = true;

                    start();
                    btnStartStop.setText(R.string.stop);
                }
            }
        });
    }

    @Override protected void onResume() {
        super.onResume();
        if (!isSetup) {
            setup();
        }
    }

    private void setup() {
        final int result = fingerPrinter.hasFingerprintsSetup();
        switch (result) {
            case FingerPrinter.SETUP_NO_HARDWARE: {
                textStatus.setText(R.string.no_hardware);
                break;
            }
            case FingerPrinter.SETUP_NO_SECURE_LOCK_SCREEN: {
                textStatus.setText(R.string.no_secure_lock_screen);
                break;
            }
            case FingerPrinter.SETUP_NO_FINGERPRINTS: {
                textStatus.setText(R.string.no_fingerprints);
                break;
            }
            case FingerPrinter.SETUP_OK: {
                fingerPrinter.init();

                isSetup = true;
                btnStartStop.setEnabled(true);
                textStatus.setText(R.string.ready_to_rock);
                break;
            }
            default: {
                textStatus.setText(R.string.no_idea);
                break;
            }
        }
    }

    @Override protected void onDestroy() {
        if (fingerPrinter != null) {
            fingerPrinter.onDestroy();
        }

        super.onDestroy();
    }

    private void start() {
        if (fingerPrinter != null) {
            fingerPrinter.startListening();
        }
    }

    private void stop() {
        if (fingerPrinter != null) {
            fingerPrinter.stopListening();
        }

        counter++;

        // only update all 10 times on automated fuzzing
        if (!isFuzzing || (counter % 10 == 0)) {
            textCounter.post(new Runnable() {
                @Override public void run() {
                    textCounter.setText(getString(R.string.counter_message, counter));
                }
            });
        }
    }

    private void startFuzzing() {
        stopFuzzing();

        textStatus.setText(R.string.fuzzing);

        isFuzzing = true;

        fuzzerTask = new FuzzerTask();
        fuzzerTask.execute();
    }

    private void stopFuzzing() {
        isFuzzing = false;
        if (fuzzerTask != null) {
            fuzzerTask.cancel(true);
            fuzzerTask = null;
        }
    }

    private final class FuzzerTask extends AsyncTask<Void, Void, Void> {
        @Override protected Void doInBackground(Void... params) {
            while (isFuzzing) {
                start();
                stop();
            }
            return null;
        }

        @Override protected void onCancelled() {
            stop();
            start();

            textStatus.setText(R.string.ready_to_rock);
        }

        @Override protected void onPostExecute(Void aVoid) {
            stop();
            start();

            textStatus.setText(R.string.ready_to_rock);
        }
    }

    private final FingerPrinter.FingerprinterCallback callback = new FingerPrinter.FingerprinterCallback() {
        @Override public void onAuthenticationError(int errMsgId, final CharSequence errString) {
            if (isFuzzing) {
                return;
            }
            textStatus.post(new Runnable() {
                @Override public void run() {
                    textStatus.setText(errString);
                }
            });
        }

        @Override public void onAuthenticationHelp(int helpMsgId, final CharSequence helpString) {
            if (isFuzzing) {
                return;
            }
            textStatus.post(new Runnable() {
                @Override public void run() {
                    textStatus.setText(helpString);
                }
            });
        }

        @Override public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            if (isFuzzing) {
                return;
            }
            textStatus.post(new Runnable() {
                @Override public void run() {
                    textStatus.setText(R.string.auth_message_success);
                    startFuzzing();
                }
            });
        }

        @Override public void onAuthenticationFailed() {
            if (isFuzzing) {
                return;
            }
            textStatus.post(new Runnable() {
                @Override public void run() {
                    textStatus.setText(R.string.auth_message_failed);
                }
            });
        }
    };
}
