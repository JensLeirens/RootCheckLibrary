package com.leirens.jens.rootchecklib.SafetyNet;
import com.leirens.jens.rootchecklib.BuildConfig;

public class SafetyNetResponse {

    private String nonce;
    private long timestampMs;
    private String apkPackageName = BuildConfig.APPLICATION_ID;
    private String[] apkCertificateDigestSha256;
    private String apkDigestSha256;
    private boolean ctsProfileMatch;
    private boolean basicIntegrity;
    private String advice = "/";

    //forces the parse()
    public SafetyNetResponse() {
    }

    /**
     * @return BASE64 encoded
     */
    public String getNonce() {
        return nonce;
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    /**
     * @return com.package.name.of.requesting.app
     */
    public String getApkPackageName() {
        return apkPackageName;
    }

    /**
     * SHA-256 hash of the certificate used to sign requesting app
     *
     * @return BASE64 encoded
     */
    public String[] getApkCertificateDigestSha256() {
        return apkCertificateDigestSha256;
    }

    /**
     * SHA-256 hash of the app's APK
     *
     * @return BASE64 encoded
     */
    public String getApkDigestSha256() {
        return apkDigestSha256;
    }


    /**
     * If the value of "ctsProfileMatch" is true, then the profile of the device running your app matches the profile of a device that has passed Android compatibility testing.
     */
    public boolean isCtsProfileMatch() {
        return ctsProfileMatch;
    }

    /**
     * If the value of "basicIntegrity" is true, then the device running your app likely wasn't tampered with, but the device has not necessarily passed Android compatibility testing.
     */
    public boolean isBasicIntegrity() {
        return basicIntegrity;
    }

    /**
     * If the device was tampered with then google sometimes returns an advice
     */
    public String getAdvice() {
        return advice;
    }

    public void setAdvice(String advice) {
        this.advice = advice;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public void setTimestampMs(long timestampMs) {
        this.timestampMs = timestampMs;
    }

    public void setApkPackageName(String apkPackageName) {
        this.apkPackageName = apkPackageName;
    }

    public void setApkCertificateDigestSha256(String[] apkCertificateDigestSha256) {
        this.apkCertificateDigestSha256 = apkCertificateDigestSha256;
    }

    public void setApkDigestSha256(String apkDigestSha256) {
        this.apkDigestSha256 = apkDigestSha256;
    }

    public void setCtsProfileMatch(boolean ctsProfileMatch) {
        this.ctsProfileMatch = ctsProfileMatch;
    }

    public void setBasicIntegrity(boolean basicIntegrity) {
        this.basicIntegrity = basicIntegrity;
    }

    @Override
    public String toString() {
        return String.format("Package Name: %s%nBasic integrity: %b%nctsProfileMatch: %b%nAdvice: %s",
                apkPackageName,basicIntegrity,ctsProfileMatch,advice);
    }
}