package burp.ui.tabs;

import burp.BurpExtender;
import burp.utils.Config;
import burp.utils.UIUtil;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;

public class BackendUIHandler {
    public enum Backends {
        BurpCollaborator, DnslogCN, Ceye, RevSuitDNS, RevSuitRMI, DnslogPlatform
    }

    private BurpExtender parent;
    private JPanel mainPanel;

    public JTabbedPane backendsPanel;
    private JComboBox<String> backendSelector;
    private JTextField ceyeIdentifierInput;
    private JTextField ceyeTokenInput;

    private JTextField revSuitRMIAdminURL;
    private JTextField revSuitRMIAddr;
    private JTextField revSuitRMIToken;

    private JTextField revSuitDNSAdminURL;
    private JTextField revSuitDNSDomain;
    private JTextField revSuitDNSToken;

    private JTextField GoDnslogAdminURL;
    private JTextField GoDnslogIdentifierInput;
    private JTextField GoDnslogTokenInput;

    private JTextField DNSLogPlatform;

    private Insets buttonMargin = new Insets(0, 3, 0, 3);


    public BackendUIHandler(BurpExtender parent) {
        this.parent = parent;
    }

    public JPanel getPanel() {
        mainPanel = new JPanel();
        mainPanel.setAlignmentX(0.0f);
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BoxLayout(mainPanel, 1));
        JPanel panel1 = UIUtil.GetXJPanel();
        backendSelector = new JComboBox(GetBackends());
        backendSelector.setMaximumSize(backendSelector.getPreferredSize());
        backendSelector.setSelectedIndex(0);

        JButton applyBtn = new JButton("Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            Config.set(Config.CURRENT_BACKEND, backendSelector.getSelectedItem().toString());
            this.apply();
        });
        applyBtn.setMargin(buttonMargin);
        panel1.add(new JLabel("Use backend: "));
        panel1.add(backendSelector);
        panel1.add(applyBtn);

        JPanel panel2 = UIUtil.GetXJPanel();
        backendsPanel = new JTabbedPane();
        backendsPanel.addTab("Ceye", getCeyePanel());
        backendsPanel.addTab("RevSuitRMI", getRevSuitRMIPanel());
        backendsPanel.addTab("RevSuitDNS", getRevSuitDNSPanel());
        backendsPanel.addTab("DNSLog Platform", getGodnslogPanel());
        panel2.add(backendsPanel);

        mainPanel.add(panel1);
        mainPanel.add(panel2);
        loadConfig();
        return mainPanel;
    }

    private void apply() {
        parent.reloadScanner();
        if (parent.scanner.getState()) {
            JOptionPane.showMessageDialog(mainPanel, "Apply success!");
        } else {
            JOptionPane.showMessageDialog(mainPanel, "Apply failed, please go to plug-in log see detail!");
        }
    }

    private JPanel getCeyePanel() {
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel1 = UIUtil.GetXJPanel();
        ceyeIdentifierInput = new JTextField(200);
        ceyeIdentifierInput.setMaximumSize(ceyeIdentifierInput.getPreferredSize());
        subPanel1.add(new JLabel("Identifier: "));
        subPanel1.add(ceyeIdentifierInput);


        JPanel subPanel2 = UIUtil.GetXJPanel();
        ceyeTokenInput = new JTextField(200);
        ceyeTokenInput.setMaximumSize(ceyeTokenInput.getPreferredSize());
        subPanel2.add(new JLabel("API Token: "));
        subPanel2.add(ceyeTokenInput);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        JButton saveBtn = new JButton("Save");
        saveBtn.setMaximumSize(saveBtn.getPreferredSize());
        saveBtn.addActionListener(e -> {
            Config.set(Config.CEYE_IDENTIFIER, ceyeIdentifierInput.getText());
            Config.set(Config.CEYE_TOKEN, ceyeTokenInput.getText());
            JOptionPane.showMessageDialog(mainPanel, "Save success!");
        });
        JButton applyBtn = new JButton("Save&Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            saveBtn.doClick();
            Config.set(Config.CURRENT_BACKEND, Backends.Ceye.name());
            this.loadConfig();
            this.apply();
        });
        saveBtn.setMargin(buttonMargin);
        applyBtn.setMargin(buttonMargin);
        subPanel3.add(saveBtn);
        subPanel3.add(applyBtn);

        panel1.add(subPanel1);
        panel1.add(subPanel2);
        panel1.add(subPanel3);
        return panel1;
    }


    private JPanel getRevSuitRMIPanel() {
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel1 = UIUtil.GetXJPanel();
        revSuitRMIAdminURL = new JTextField(200);
        revSuitRMIAdminURL.setMaximumSize(revSuitRMIAdminURL.getPreferredSize());
        subPanel1.add(new JLabel("RevSuit Admin URL: "));
        subPanel1.add(revSuitRMIAdminURL);

        JPanel subPanel2 = UIUtil.GetXJPanel();
        revSuitRMIAddr = new JTextField(200);
        revSuitRMIAddr.setMaximumSize(revSuitRMIAddr.getPreferredSize());
        subPanel2.add(new JLabel("RevSuit RMI Addr: "));
        subPanel2.add(revSuitRMIAddr);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        revSuitRMIToken = new JTextField(200);
        revSuitRMIToken.setMaximumSize(revSuitRMIToken.getPreferredSize());
        subPanel3.add(new JLabel("RevSuit Token: "));
        subPanel3.add(revSuitRMIToken);

        JPanel subPanel4 = UIUtil.GetXJPanel();
        JButton saveBtn = new JButton("Save");
        saveBtn.setMaximumSize(saveBtn.getPreferredSize());
        saveBtn.addActionListener(e -> {
            Config.set(Config.REVSUIT_RMI_ADMIN_URL, revSuitRMIAdminURL.getText());
            Config.set(Config.REVSUIT_RMI_ADDR, revSuitRMIAddr.getText());
            Config.set(Config.REVSUIT_RMI_TOKEN, revSuitRMIToken.getText());
            JOptionPane.showMessageDialog(mainPanel, "Save success!");
        });
        JButton applyBtn = new JButton("Save&Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            saveBtn.doClick();
            Config.set(Config.CURRENT_BACKEND, Backends.RevSuitRMI.name());
            this.loadConfig();
            this.apply();
        });
        saveBtn.setMargin(buttonMargin);
        applyBtn.setMargin(buttonMargin);
        subPanel4.add(saveBtn);
        subPanel4.add(applyBtn);

        panel1.add(subPanel1);
        panel1.add(subPanel2);
        panel1.add(subPanel3);
        panel1.add(subPanel4);
        return panel1;
    }

    private JPanel getRevSuitDNSPanel() {
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel1 = UIUtil.GetXJPanel();
        revSuitDNSAdminURL = new JTextField(200);
        revSuitDNSAdminURL.setMaximumSize(revSuitDNSAdminURL.getPreferredSize());
        subPanel1.add(new JLabel("RevSuit Admin URL: "));
        subPanel1.add(revSuitDNSAdminURL);

        JPanel subPanel2 = UIUtil.GetXJPanel();
        revSuitDNSDomain = new JTextField(200);
        revSuitDNSDomain.setMaximumSize(revSuitDNSDomain.getPreferredSize());
        subPanel2.add(new JLabel("RevSuit Domain Root: "));
        subPanel2.add(revSuitDNSDomain);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        revSuitDNSToken = new JTextField(200);
        revSuitDNSToken.setMaximumSize(revSuitDNSToken.getPreferredSize());
        subPanel3.add(new JLabel("RevSuit Token: "));
        subPanel3.add(revSuitDNSToken);

        JPanel subPanel4 = UIUtil.GetXJPanel();
        JButton saveBtn = new JButton("Save");
        saveBtn.setMaximumSize(saveBtn.getPreferredSize());
        saveBtn.addActionListener(e -> {
            Config.set(Config.REVSUIT_DNS_ADMIN_URL, revSuitDNSAdminURL.getText());
            Config.set(Config.REVSUIT_DNS_DOMAIN, revSuitDNSDomain.getText());
            Config.set(Config.REVSUIT_DNS_TOKEN, revSuitDNSToken.getText());
            JOptionPane.showMessageDialog(mainPanel, "Save success!");
        });
        JButton applyBtn = new JButton("Save&Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            saveBtn.doClick();
            Config.set(Config.CURRENT_BACKEND, Backends.RevSuitDNS.name());
            this.loadConfig();
            this.apply();
        });
        saveBtn.setMargin(buttonMargin);
        applyBtn.setMargin(buttonMargin);
        subPanel4.add(saveBtn);
        subPanel4.add(applyBtn);

        panel1.add(subPanel1);
        panel1.add(subPanel2);
        panel1.add(subPanel3);
        panel1.add(subPanel4);
        return panel1;
    }

    private JPanel getGodnslogPanel() {
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel4 = UIUtil.GetXJPanel();
        GoDnslogAdminURL = new JTextField(200);
        GoDnslogAdminURL.setMaximumSize(revSuitDNSAdminURL.getPreferredSize());
        subPanel4.add(new JLabel("DNSLog Platform URL: "));
        subPanel4.add(GoDnslogAdminURL);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        JButton saveBtn = new JButton("Save");
        saveBtn.setMaximumSize(saveBtn.getPreferredSize());
        saveBtn.addActionListener(e -> {
            Config.set(Config.DNSLog_Platform, GoDnslogAdminURL.getText());
            JOptionPane.showMessageDialog(mainPanel, "Save success!");
        });
        JButton applyBtn = new JButton("Save&Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            saveBtn.doClick();
            Config.set(Config.CURRENT_BACKEND, Backends.DnslogPlatform.name());
            this.loadConfig();
            this.apply();
        });
        saveBtn.setMargin(buttonMargin);
        applyBtn.setMargin(buttonMargin);
        subPanel3.add(saveBtn);
        subPanel3.add(applyBtn);

        panel1.add(subPanel4);
        panel1.add(subPanel3);
        return panel1;
    }

    private void loadConfig() {
        backendSelector.setSelectedItem(Config.get(Config.CURRENT_BACKEND, Backends.BurpCollaborator.name()));

        ceyeIdentifierInput.setText(Config.get(Config.CEYE_IDENTIFIER));
        ceyeTokenInput.setText(Config.get(Config.CEYE_TOKEN));

        revSuitRMIAdminURL.setText(Config.get(Config.REVSUIT_RMI_ADMIN_URL));
        revSuitRMIAddr.setText(Config.get(Config.REVSUIT_RMI_ADDR));
        revSuitRMIToken.setText(Config.get(Config.REVSUIT_RMI_TOKEN));

        revSuitDNSAdminURL.setText(Config.get(Config.REVSUIT_DNS_ADMIN_URL));
        revSuitDNSDomain.setText(Config.get(Config.REVSUIT_DNS_DOMAIN));
        revSuitDNSToken.setText(Config.get(Config.REVSUIT_DNS_TOKEN));

        //GoDnslogIdentifierInput.setText(Config.get(Config.GODNSLOG_IDENTIFIER));
        //GoDnslogTokenInput.setText(Config.get(Config.GODNSLOG_TOKEN));
        GoDnslogAdminURL.setText(getAdminUrl());
    }

    public String getAdminUrl() {
        String adminUrl = Config.get(Config.GODNSLOG_ADMIN_URL, null);
        if (adminUrl == null && Config.get(Config.GODNSLOG_IDENTIFIER, null) != null) {
            adminUrl = "http://" + Config.get(Config.GODNSLOG_IDENTIFIER);
        }
        return adminUrl;
    }

    private String[] GetBackends() {
        ArrayList<String> algStrs = new ArrayList<String>();
        Backends[] backends = Backends.values();
        for (Backends backend : backends) {
            algStrs.add(backend.name().replace('_', '/'));
        }
        return algStrs.toArray(new String[algStrs.size()]);
    }
}
