package com.example.myproject;

import java.io.File;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.view.Menu;
import android.view.MenuItem;
import android.content.res.AssetManager;
import android.widget.TextView;

public class MainActivity extends Activity {

    static {
    	    	       
//        System.loadLibrary("ssl");
//        System.loadLibrary("crypto");
        System.loadLibrary("glib");
        System.loadLibrary("gmp");
        System.loadLibrary("pbc"); 
        //System.loadLibrary("ssl_static_shared");
        //System.loadLibrary("crypto_static_shared");
        System.loadLibrary("tester");          
    }
    
    //System.loadLibrary("ssl_static");
    

    
	public static native void InitMainActivityjni();
	public native String doSomething(AssetManager assetManager);
	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		//setContentView(R.layout.activity_main);
		
        String sd_path = Environment.getExternalStorageDirectory().getAbsolutePath();
		//String sd_path = getApplication().getFilesDir().getAbsolutePath();
        //String fileName = string.txt
        String file_path = sd_path + File.separator + "string.txt";
        System.out.println(file_path);
        System.out.println(sd_path);        
		
		TextView  tv = new TextView(this);
		AssetManager assetManager = getResources().getAssets();
        tv.setText(doSomething(assetManager));
        setContentView(tv);       
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
	
}
