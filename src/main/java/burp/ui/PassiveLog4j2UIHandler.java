package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.ITab;
import burp.ui.tabs.BackendUIHandler;
import burp.ui.tabs.FuzzUIHandler;
import burp.ui.tabs.POCUIHandler;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;

public class PassiveLog4j2UIHandler implements ITab {
    public JTabbedPane mainPanel;
    public BurpExtender parent;

    public PassiveLog4j2UIHandler(BurpExtender parent) {
        this.parent = parent;
        this.initUI();
    }

    private void initUI() {
        this.mainPanel = new JTabbedPane();
        BackendUIHandler bui = new BackendUIHandler(parent);
        POCUIHandler pui = new POCUIHandler(parent);
        FuzzUIHandler fui = new FuzzUIHandler(parent);
        this.mainPanel.addTab("Backend", bui.getPanel());
        this.mainPanel.addTab("POC", pui.getPanel());
        this.mainPanel.addTab("Fuzz", fui.getPanel());
    }

    @Override
    public String getTabCaption() {
        return "Passive Log4j2";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
