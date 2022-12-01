package com.agronod.keycloak.config;

import java.io.File;
import java.util.Iterator;

import org.apache.commons.configuration2.FileBasedConfiguration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class configLoader {

    private static configLoader instance;
    private FileBasedConfiguration configuration;

    private configLoader() {
        Parameters params = new Parameters();
        File propertiesFile = new File("emailauthapplication.properties");

        FileBasedConfigurationBuilder<FileBasedConfiguration> builder = new FileBasedConfigurationBuilder<FileBasedConfiguration>(
                PropertiesConfiguration.class)
                .configure(params.properties()
                        .setFile(propertiesFile));
        try {
            configuration = builder.getConfiguration();
            System.out.println("Config: " + configuration.toString());
            System.out.println("Config: " + configuration.isEmpty());
            System.out.println("Config: " + configuration.size());
            for (Iterator<String> i = configuration.getKeys(); i.hasNext();) {
                String key = i.next();
                System.out.println("keys:" + key);
            }

        } catch (ConfigurationException e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public static synchronized configLoader getInstance() {
        if (instance == null) {
            instance = new configLoader();
            System.out.println(instance);
        }
        return instance;
    }

    public String getProperty(String key) {
        return (String) configuration.getProperty(key);
    }
}