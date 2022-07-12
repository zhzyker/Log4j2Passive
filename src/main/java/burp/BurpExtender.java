package burp;

import burp.scanner.PassiveLog4j2ner;
import burp.ui.PassiveLog4j2UIHandler;
import burp.utils.Utils;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public String version = "0.2";
    public PassiveLog4j2UIHandler uiHandler;
    public PassiveLog4j2ner scanner;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Utils.Callback = this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Passive Log4j2");
        this.stdout.println("Passive Log4j2 v" + version + " change by zhzyker");
        this.uiHandler = new PassiveLog4j2UIHandler(this);
        callbacks.addSuiteTab(this.uiHandler);
        this.reloadScanner();
        callbacks.registerExtensionStateListener(this);
    }

    public void reloadScanner() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
        scanner = new PassiveLog4j2ner(this);
        callbacks.registerScannerCheck(scanner);
    }

    @Override
    public void extensionUnloaded() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
    }
}
