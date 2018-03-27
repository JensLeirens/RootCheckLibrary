package com.leirens.jens.rootchecklib.SafetyNet;

import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SafetyNetHelper {

    private SafetyNetResponse safetyNetResponse;
    private final String TAG = SafetyNetHelper.class.getSimpleName();

    public SafetyNetHelper() {
    }

    public SafetyNetResponse getSafetyNetResponse() {
        return safetyNetResponse;
    }

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
}
