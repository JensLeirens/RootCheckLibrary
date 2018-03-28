package com.leirens.jens.rootchecklib.SafetyNet;

import android.app.Activity;
import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;
import android.view.View;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.leirens.jens.rootchecklib.BuildConfig;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

public class SafetyNetHelper {

    private SafetyNetResponse safetyNetResponse;
    private final String TAG = SafetyNetHelper.class.getSimpleName();

    public SafetyNetHelper() {
    }

    public SafetyNetResponse getSafetyNetResponse() {
        return safetyNetResponse;
    }

    /**
     * Parse the JWS string into a decoded JWT
     *
     * @param jwsResult JWS String that is recieved from the google SafetNet Api
     */
    public void parseJWS(String jwsResult){

        if (jwsResult != null) {

            //the JWT (JSON WEB TOKEN) is just a 3 base64 encoded parts concatenated by a . character
            final String[] jwtParts = jwsResult.split("\\.");

            if (jwtParts.length == 3) {
                //we're only really interested in the body/payload
                String decodedPayload = new String(Base64.decode(jwtParts[1], Base64.DEFAULT));
                parse(decodedPayload);
            }
        }
    }

    /**
     * Parse the JSON string into populated SafetyNetResponse object
     *
     * @param decodedJWTPayload JSON String (always a json string according to JWT spec)
     */
    private void parse(@NonNull String decodedJWTPayload) {
        safetyNetResponse = new SafetyNetResponse();

        Log.d(TAG, "decodedJWTPayload json:" + decodedJWTPayload);

        try {
            JSONObject root = new JSONObject(decodedJWTPayload);
            if (root.has("nonce")) {
                safetyNetResponse.setNonce(root.getString("nonce"));
            }

            if (root.has("apkCertificateDigestSha256")) {
                JSONArray jsonArray = root.getJSONArray("apkCertificateDigestSha256");
                if (jsonArray != null) {
                    String[] certDigests = new String[jsonArray.length()];
                    for (int i = 0; i < jsonArray.length(); i++) {
                        certDigests[i] = jsonArray.getString(i);
                    }
                    safetyNetResponse.setApkCertificateDigestSha256(certDigests);
                }
            }

            if (root.has("apkDigestSha256")) {
                safetyNetResponse.setApkDigestSha256(root.getString("apkDigestSha256"));
            }

            if (root.has("apkPackageName")) {
                safetyNetResponse.setApkPackageName(root.getString("apkPackageName"));
            }

            if (root.has("basicIntegrity")) {
                safetyNetResponse.setBasicIntegrity(root.getBoolean("basicIntegrity"));
            }

            if (root.has("ctsProfileMatch")) {
                safetyNetResponse.setCtsProfileMatch(root.getBoolean("ctsProfileMatch"));
            }

            if (root.has("timestampMs")) {
                safetyNetResponse.setTimestampMs(root.getLong("timestampMs"));
            }

            if (root.has("advice")) {
                safetyNetResponse.setAdvice(root.getString("advice"));
            }

        } catch (JSONException e) {
            Log.e(TAG, "problem parsing decodedJWTPayload:" + e.getMessage(), e);
        }
    }

    /**
     * Sends the request to the google api and handles the response for you.
     * the api call happens asynchronously
     * you problably want to implement this yourself
     * @param callingActivity the activty that want to make the request
     * @param apikey your api key from google to call the SafetyNet service
     */
    public void sendRequest(Activity callingActivity, String apikey) {
        String nonceData = "RootChecker application: " + System.currentTimeMillis();
        byte[] nonce = getRequestNonce(nonceData);

        // first get a safetynetclient for the foreground activity
        SafetyNetClient client = SafetyNet.getClient(callingActivity.getApplicationContext());

        // make the call
        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce , apikey);
        task.addOnSuccessListener(callingActivity, mSucceslistener)
                .addOnFailureListener(callingActivity, mFailureListener);
    }

    private OnSuccessListener<SafetyNetApi.AttestationResponse> mSucceslistener = new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
        @Override
        public void onSuccess(SafetyNetApi.AttestationResponse attestationResponse) {
            String mResult;
            mResult = attestationResponse.getJwsResult();
            Log.d("SafetenetAPI", "Succes; Result= " + mResult);
            parseJWS(mResult);
        }
    };

    private OnFailureListener mFailureListener = new OnFailureListener() {
        @Override
        public void onFailure(@NonNull Exception e) {

            if ( e instanceof ApiException) {
                ApiException apiException = (ApiException) e ;
                Log.e("SafetyNetAPI", "API exception Error: " + CommonStatusCodes.getStatusCodeString(apiException.getStatusCode())
                        + ": " + apiException.getStatusCode() + " message: " + e.getMessage()) ;
            } else {
                Log.e("SafetyNetAPI", "Error: " + e.getMessage()) ;
            }
        }
    };

    /**
     * converts the data string to an array of bytes
     *
     * @param data String that you want to convert to an array of bytes
     */
    private byte[] getRequestNonce(String data) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

        final Random mRandom = new SecureRandom();
        byte[] bytes = new byte[24];
        mRandom.nextBytes(bytes);
        try {
            byteStream.write(bytes);
            byteStream.write(data.getBytes());
        } catch (IOException e) {
            return null;
        }

        return byteStream.toByteArray();
    }
}
