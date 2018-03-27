package com.leirens.jens.rootchecklib;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class RootChecker {

    private List<String> reasons;
    private Context c;

    public RootChecker(Context c) {
        this.c = c ;
        this.reasons = new ArrayList<>();
    }

    public List<String> getReasons() {
        return reasons;
    }

    public boolean isDeviceRooted() {
        reasons.clear();

        // App checks
        boolean rootManagementAppFound = detectRootManagementApps();
        boolean dangerousAppsFound = detectPotentiallyDangerousApps();
        boolean rootCloakingAppFound = detectRootCloakingApps();

        // Paths and Binary checks
        boolean suPathFound = checkForSUPath();
        boolean suBinaryFound = checkForSuBinary();
        boolean magiskFound = checkForMagiskBinary();
        boolean busyboxFound = checkForBusyBoxBinary();
        boolean rwPathsFound = checkForRWPaths();
        boolean dangerousPropertiesFound = checkForDangerousProps();
        boolean testkeyFound = checkForTestKeys();
        boolean devKeyFound = checkForDevKeys();

        // external monitoring
        /*boolean usbDebuggingEnabled =*/ checkRootMethodUSBDebug();

        //emulator check
        boolean checkForEmulator = checkForEmulator();

        //native check
        boolean checkNative = rootcheckNative();


        return testkeyFound || suPathFound || suBinaryFound || rootManagementAppFound || dangerousAppsFound || rootCloakingAppFound || magiskFound || busyboxFound || rwPathsFound
                || dangerousPropertiesFound || devKeyFound || checkForEmulator || checkNative;
    }

    /**
     * Checks if there are test-keys
     * @return - true if test-keys are found
     */
    private boolean checkForTestKeys() {
        String buildTags = Build.TAGS;
        if ( buildTags != null && buildTags.contains("test-keys")){
            Log.i("checkForTestKeys", "Test keys found = True");
            reasons.add("Test keys found");
            return true ;
        } else {

            Log.i("checkForTestKeys", "Test keys found =False");
            return false;
        }
    }

    /**
     * Checks if there are test-keys
     * @return - true if test-keys are found
     */
    private boolean checkForDevKeys() {
        String buildTags = Build.TAGS;
        if ( buildTags != null && buildTags.contains("dev-keys")){
            Log.i("checkForDevKeys", "Dev keys found = True");
            reasons.add("Dev keys found");
            return true ;
        } else {

            Log.i("checkForDevKeys", "Dev keys found =False");
            return false;
        }
    }

    /**
     * Checks if there is a path SU
     * @return - true if a path with SU is found
     */
    private boolean checkForSUPath() {
        boolean check = false ;
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                check =  true;
            }
        }
        if(check){
            reasons.add("Path SU found");
            Log.i("checkforSUPath", "SU path found = True");
            checkRootMethod2A();
            return true;
        }
        Log.i("checkforSUPath", "False");
        return false;
    }

    /**
     * if there are SU paths check the UID, this might trigger authorization from a root management app
     */
    private void checkRootMethod2A(){
        Process process = null;
        try {
            process = new ProcessBuilder().command("su", "-c", "id").start();
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = in.readLine();
            if (output != null && output.toLowerCase().contains("uid=0"))
                reasons.add("Root access is available");
            Log.i("Root access", "isRootGiven= True");


        } catch (Exception e) {
            Log.e("Root access", e.toString());

        } finally {
            if (process != null)
                try {
                    process.destroy();
                } catch (Exception e){
                    Log.e("Root access", e.toString());
                }
        }
    }

    /**
     * Checks if the usb debugging is enabled
     * @return - true if debugging is enabled
     */
    private boolean checkRootMethodUSBDebug(){
        //Tested
        //If it is enabled, adb == 1, otherwise adb == 0
        int adb = Settings.Secure.getInt(c.getContentResolver(), Settings.Secure.ADB_ENABLED, 0);
        if (adb == 1 ) {
            Log.i("USB debugging", "USB debugging = True");
            reasons.add("USB debugging enabled");
            return true;
        } else {
            Log.i("USB debugging", "USB debugging = False");
            return false;
        }
    }

    /**
     * Using the PackageManager, check for a list of well known root apps. @link {Const.knownRootAppsPackages}
     * @return true if one of the apps it's installed
     */
    private boolean detectRootManagementApps() {
        // Create a list of package names to iterate over from constants
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(Const.knownRootAppsPackages));

        if (isAnyPackageFromListInstalled(packages)) {
            Log.i("Root management apps", "True");
            return true ;
        }
        Log.i("Root management apps", "False");
        return false;
    }

    /**
     * Using the PackageManager, check for a list of well known root apps. @link {Const.knownDangerousAppsPackages}
     * @return true if one of the apps it's installed
     */
    private boolean detectPotentiallyDangerousApps() {
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(Const.knownDangerousAppsPackages));
        if (isAnyPackageFromListInstalled(packages)) {
            Log.i("Dangerous apps", "True");
            return true ;
        }
        Log.i("Dangerous apps", "False");
        return false;
    }

    /**
     * Using the PackageManager, check for a list of well known root apps. @link {Const.knownRootCloakingPackages}
     * @return true if one of the apps it's installed
     */
    private boolean detectRootCloakingApps() {
        ArrayList<String> packages = new ArrayList<>(Arrays.asList(Const.knownRootCloakingPackages));
        if (isAnyPackageFromListInstalled(packages)) {
            Log.i("RootCloaking apps", "True");
            return true ;
        }
        Log.i("RootCloaking apps", "False");
        return false;
    }

    /**
     * Checks various (Const.suPaths) common locations for the SU binary
     * @return true if SU binary has been found
     */
    private boolean checkForSuBinary(){
        return checkForBinary("su");
    }

    /**
     * Checks various (Const.suPaths) common locations for the magisk binary (a well know root level program)
     * @return true if magisk has been found
     */
    private boolean checkForMagiskBinary(){
        return checkForBinary("magisk");
    }

    /**
     * Checks various (Const.suPaths) common locations for the busybox binary (a well know root level program)
     * @return true if busybox has been found
     */
    private boolean checkForBusyBoxBinary(){
        return checkForBinary("busybox");
    }

    /**
     * Checks the binaries with the given parameter
     * @param filename the name of the file that needs to be checked
     * @return true if a binary with that filename has been found
     */
    private boolean checkForBinary(String filename) {

        String[] pathsArray = Const.suPaths;

        boolean result = false;

        for (String path : pathsArray) {
            String completePath = path + filename;
            File f = new File(path, filename);
            boolean fileExists = f.exists();
            if (fileExists) {
                reasons.add(completePath + " binary detected");

                result = true;
            }
        }
        Log.i("checkForBinary",filename + " = " + String.valueOf(result));
        return result;
    }

    /**
     * Gets the mounts of the device
     * @return - The different mounts of the device
     */
    private String[] mountReader() {
        String[] result = new String[0];
        try {
            InputStream inputstream = Runtime.getRuntime().exec("mount").getInputStream();
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            result = propVal.split("\n");
        } catch (IOException | NoSuchElementException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Gets the properties of the device
     * @return - the different properties of the device
     */
    private String[] propsReader() {
        String[] result = new String[0];
        try {
            InputStream inputstream = Runtime.getRuntime().exec("getprop").getInputStream();
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            result = propVal.split("\n");
        } catch (IOException | NoSuchElementException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Checks for several system properties for
     * @return - true if dangerous props are found
     */
    private boolean checkForDangerousProps() {

        final Map<String, String> dangerousProps = new HashMap<>();
        dangerousProps.put("ro.debuggable", "1");
        dangerousProps.put("ro.secure", "0");

        boolean result = false;

        String[] lines = propsReader();
        for (String line : lines) {
            for (String key : dangerousProps.keySet()) {
                if (line.contains(key)) {
                    String badValue = dangerousProps.get(key);
                    badValue = "[" + badValue + "]";
                    if (line.contains(badValue)) {
                        //logging and adding to reasons
                        Log.i("checkForDangerousProps",key + " = " + badValue + " detected!");
                        reasons.add("Dangerous Property detected: " + key + " = " + badValue );
                        result = true;
                    } else {
                        Log.i("checkForDangerousProps",key + " = " + badValue + " not detected");

                    }
                }
            }
        }
        return result;
    }

    /**
     * Checks the RW paths that you should not be able to write
     * @return - true if RW paths have been found
     */
    private boolean checkForRWPaths() {

        boolean result = false;

        String[] lines = mountReader();
        for (String line : lines) {

            // Split lines into parts
            String[] args = line.split(" ");

            if (args.length < 4){
                // If we don't have enough options per line, skip this and log an error
                Log.e("checkForRWPaths","Error formatting mount line: "+line);
                continue;
            }

            String mountPoint = args[1];
            String mountOptions = args[3];

            for(String pathToCheck: Const.pathsThatShouldNotBeWrtiable) {
                if (mountPoint.equalsIgnoreCase(pathToCheck)) {

                    // Split options out and compare against "rw" to avoid false positives
                    for (String option : mountOptions.split(",")){

                        if (option.equalsIgnoreCase("rw")){
                            Log.i("checkForRWPaths",pathToCheck+" path is mounted with rw permissions! "+line);
                            reasons.add("Following RW path was detected: " + pathToCheck);
                            result = true;
                            break;
                        }
                    }
                }
            }
        }

        return result;
    }

    /**
     * Check if any package in the list is installed
     * @param packages - list of packages to search for
     * @return true if any of the packages are installed
     */
    private boolean isAnyPackageFromListInstalled(List<String> packages){
        boolean result = false;

        PackageManager pm = c.getPackageManager();

        for (String packageName : packages) {
            try {
                // Root app detected
                pm.getPackageInfo(packageName, 0);
                Log.i("PackageChecker",packageName + " ROOT app detected!");
                reasons.add("Root app detected: " + packageName);
                result = true;
            } catch (PackageManager.NameNotFoundException e) {
                // Exception thrown, package is not installed into the system
            }
        }

        return result;
    }

    /**
     * Check if the device is an emulator
     * @return true if the device is an emulator
     */
    private boolean checkForEmulator(){
        boolean emulated = false ;

        // The name of the underlying board for emulators its "unknown".
        if(Build.BOARD.contains("unknown")) {
            emulated = true ;
            Log.i("checkForEmulator Board" , Build.BOARD + " = true");
            reasons.add("Emulator detected: Unknown board");
        }

        // sometimes there is no bootloader so there is a false positive
        /*// The bootloader, for emulators its "unknown".
        if(Build.BOOTLOADER.contains("unknown")) {
            emulated = true ;
            reasons.add("Emulator detected: no bootloader");
        }*/

        // The name of device, for emulators its generic_x86
        if(Build.DEVICE.contains("generic")) {
            emulated = true ;
            Log.i("checkForEmulator Board" , Build.DEVICE + " = true");
            reasons.add("Emulator detected: device contains generic");
        }

        // The name of the hardware  "goldfish" or newer like "ranchu"
        if(Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu")) {
            emulated = true ;
            Log.i("checkForEmulator Board" , Build.HARDWARE + " = true");
            reasons.add("Emulator detected: Hardware contained goldfish or ranchu");
        }

        // The end-user-visible name for the end product. "SDK"
        if(Build.MODEL.toUpperCase().contains("SDK") || Build.MODEL.toUpperCase().contains("GENERIC") ) {
            emulated = true ;
            Log.i("checkForEmulator Board" , Build.MODEL + " = true");
            reasons.add("Emulator detected: Build Model contains SDK or generic");
        }

        // The name of the overall product. for emulators it contains sdk_gphone_x86
        if(Build.PRODUCT.contains("sdk")){
            emulated = true ;
            Log.i("checkForEmulator Board" , Build.PRODUCT + " = true");
            reasons.add("Emulator detected: product name contained SDK ");
        }

        return emulated;
    }

    public boolean rootcheckNative(){
        String binaryName = "su";
        Map values = new HashMap();
        String[] paths = new String[Const.suPaths.length];
        for (int i = 0; i < paths.length; i++) {
            paths[i] = Const.suPaths[i]+binaryName;
            values.put(i,paths[i]);
        }

        boolean binaryFound = false ;
        for(int i : checkForRootNative(paths)){
            if(i == 1 ){
                binaryFound = true;
                reasons.add("Native found binary: " + values.get(i));
            }
        }

        return binaryFound ;
    }


    static {
        System.loadLibrary("native-lib");
    }

    private native int[] checkForRootNative(String[] paths);
}
