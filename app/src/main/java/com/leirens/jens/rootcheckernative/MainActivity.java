package com.leirens.jens.rootcheckernative;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.TabLayout;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.leirens.jens.rootchecklib.SafetyNet.SafetyNetHelper;
import com.squareup.picasso.Picasso;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity {

    @BindView(R.id.tvResult)
    TextView tvResult;

    @BindView(R.id.tablayout)
    TabLayout tabLayout;

    @BindView(R.id.progressBar)
    ProgressBar spinner;

    @BindView(R.id.check)
    Button check;

    @BindView(R.id.rootedCheckImage)
    ImageView checkedImage;

    private SafetyNetHelper safetyNetHelper = new SafetyNetHelper();

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        spinner.setVisibility(View.VISIBLE);
        check.setVisibility(View.GONE);
        checkRoot();
        tabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab tab) {
                checkedImage.setVisibility(View.GONE);
                if (tab.getPosition() == 0) {
                    check.setVisibility(View.GONE);
                    checkRoot();
                } else {
                    if (safetyNetHelper.getSafetyNetResponse() != null) {
                        tvResult.setText(safetyNetHelper.getSafetyNetResponse().toString());
                        checkedImage.setVisibility(View.VISIBLE);
                        if (safetyNetHelper.getSafetyNetResponse().isCtsProfileMatch()) {
                            Picasso.with(getApplicationContext()).load(R.drawable.greencheck).into(checkedImage);
                        } else {
                            Picasso.with(getApplicationContext()).load(R.drawable.redcross).into(checkedImage);
                        }

                    } else {
                        check.setVisibility(View.VISIBLE);
                        tvResult.setText("");
                        checkedImage.setVisibility(View.GONE);
                    }
                }
            }

            @Override
            public void onTabUnselected(TabLayout.Tab tab) {

            }

            @Override
            public void onTabReselected(TabLayout.Tab tab) {

            }
        });
    }

    private void checkRoot() {
        RootChecker rootChecker = new RootChecker(getApplicationContext());
        boolean isRooted =  rootChecker.isDeviceRooted();
        StringBuilder sb = new StringBuilder();

        for(String s : rootChecker.getReasons()){
            sb.append("\n");
            sb.append(s);
        }
        if(isRooted){
            Picasso.with(getApplicationContext()).load(R.drawable.redcross).into(checkedImage);
        }else {
            Picasso.with(getApplicationContext()).load(R.drawable.greencheck).into(checkedImage);
        }
        tvResult.setText(String.format("Tempered device: %b \n\nReasons: %s",isRooted, sb.toString()));
        checkedImage.setVisibility(View.VISIBLE);
        spinner.setVisibility(View.GONE);

    }

    @OnClick(R.id.check)
    public void sendRequest() {
        spinner.setVisibility(View.VISIBLE);
        String nonceData = "RootChecker application: " + System.currentTimeMillis();
        byte[] nonce = getRequestNonce(nonceData);

        // first get a safetynetclient for the foreground activity
        SafetyNetClient client = SafetyNet.getClient(this.getApplicationContext());

        // make the call
        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce , BuildConfig.API_KEY);
        task.addOnSuccessListener(this, mSucceslistener)
                .addOnFailureListener(this, mFailureListener);
    }

    private OnSuccessListener<SafetyNetApi.AttestationResponse> mSucceslistener = new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
        @Override
        public void onSuccess(SafetyNetApi.AttestationResponse attestationResponse) {
            String mResult;
            mResult = attestationResponse.getJwsResult();
            Log.d("SafetenetAPI", "Succes; Result= " + mResult);
            safetyNetHelper.parseJWS(mResult);
            tvResult.setText(safetyNetHelper.getSafetyNetResponse().toString());
            if(!safetyNetHelper.getSafetyNetResponse().isCtsProfileMatch()){
                Picasso.with(getApplicationContext()).load(R.drawable.redcross).into(checkedImage);
            }else {
                Picasso.with(getApplicationContext()).load(R.drawable.greencheck).into(checkedImage);
            }
            checkedImage.setVisibility(View.VISIBLE);
            spinner.setVisibility(View.GONE);
            check.setVisibility(View.GONE);

        }
    };

    private OnFailureListener mFailureListener = new OnFailureListener() {
        @Override
        public void onFailure(@NonNull Exception e) {
            tvResult.setText(R.string.callFailed);
            spinner.setVisibility(View.GONE);
            if ( e instanceof ApiException) {
                ApiException apiException = (ApiException) e ;
                Log.e("SafetyNetAPI", "API exception Error: " + CommonStatusCodes.getStatusCodeString(apiException.getStatusCode())
                        + ": " + apiException.getStatusCode() + " message: " + e.getMessage()) ;
            } else {
                Log.e("SafetyNetAPI", "Error: " + e.getMessage()) ;
            }
        }
    };

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
