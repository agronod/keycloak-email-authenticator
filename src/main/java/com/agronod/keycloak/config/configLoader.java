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
        ClassLoader moduleClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(PropertiesConfiguration.class.getClassLoader());

        Parameters params = new Parameters();
        File propertiesFile = new File("emailauthapplication.properties");

        FileBasedConfigurationBuilder<FileBasedConfiguration> builder = new FileBasedConfigurationBuilder<FileBasedConfiguration>(
                PropertiesConfiguration.class)
                .configure(params.properties()
                        .setFile(propertiesFile));
        try {
            configuration = builder.getConfiguration();
            Thread.currentThread().setContextClassLoader(moduleClassLoader);

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