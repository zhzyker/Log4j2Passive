package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Config;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

import static burp.utils.HttpUtils.GetDefaultRequest;


public class DnslogPlatform implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();

    String token = "";
    String baseUrl;
    String rootDomain = "";
    String dnsLogResultCache = "";
    Timer timer = new Timer();

    public DnslogPlatform() {
        this.baseUrl = Config.get(Config.DNSLog_Platform);
        if (baseUrl != null) {
            this.initDomain();
        } else {
            Utils.Callback.printOutput("Please Input DNSLog_Platform URL");
        }
    }

    private void initDomain() {
        try {
            Utils.Callback.printOutput("Get domain...");
            Response resp = client.newCall(GetDefaultRequest(baseUrl + "/new_gen").build()).execute();
            JSONObject jObj = JSON.parseObject(resp.body().string());
            rootDomain = jObj.getString("domain");
            token = jObj.getString("token");
            Utils.Callback.printOutput(String.format("Domain: %s", rootDomain));
            Utils.Callback.printOutput(String.format("Token: %s", token));
            startSessionHeartbeat();
        } catch (Exception ex) {
            Utils.Callback.printError("initDomain failed: " + ex.getMessage());
        }
    }

    private void startSessionHeartbeat() {
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                flushCache();
            }
        }, 0, 2 * 60 * 1000); //2min
    }


    @Override
    public boolean supportBatchCheck() {
        return false;
    }

    @Override
    public String getName() {
        return "https://github.com/yumusb/DNSLog-Platform-Golang";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5).toLowerCase() + "." + rootDomain;
    }

    @Override
    public String[] batchCheck(String[] payloads) {
        return new String[0];
    }


    @Override
    public boolean CheckResult(String domain) {
        return dnsLogResultCache.contains(domain.toLowerCase());
    }

    @Override
    public boolean flushCache(int count) {
        return flushCache();
    }

    public boolean flushCache() {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(baseUrl + "/" +token).build()).execute();
            dnsLogResultCache = resp.body().string().toLowerCase();
            Utils.Callback.printOutput(String.format("Get Result: %s", dnsLogResultCache));
            return true;
        } catch (Exception ex) {
            Utils.Callback.printOutput(String.format("Get Result Failed: %s", ex.getMessage()));
            return false;
        }
    }

    @Override
    public boolean getState() {
        return true;
    }

    @Override
    public void close() {
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_LDAP, IPOC.POC_TYPE_RMI};
    }
}
