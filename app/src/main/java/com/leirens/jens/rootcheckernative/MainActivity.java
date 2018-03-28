package com.leirens.jens.rootcheckernative;

import android.os.Bundle;
import android.support.design.widget.TabLayout;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.leirens.jens.rootchecklib.RootChecker;
import com.leirens.jens.rootchecklib.SafetyNet.SafetyNetHelper;
import com.squareup.picasso.Picasso;

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
        safetyNetHelper.sendRequest(this,BuildConfig.API_KEY);
    }

}
