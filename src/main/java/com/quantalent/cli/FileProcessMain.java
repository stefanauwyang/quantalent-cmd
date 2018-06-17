package com.quantalent.cli;

import com.quantalent.cli.exception.FileProcessRuntimeException;
import com.quantalent.cli.model.Config;
import com.quantalent.commons.StatusCode;
import com.quantalent.commons.exception.BaseException;
import com.quantalent.commons.exception.BaseRuntimeException;
import com.quantalent.crypto.CryptoSymService;
import com.quantalent.crypto.HashService;
import com.quantalent.crypto.hash.HashServiceFactory;
import com.quantalent.crypto.model.Algorithm;
import com.quantalent.crypto.sym.CryptoSymServiceFactory;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.util.Base64;

@SpringBootApplication
public class FileProcessMain implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessMain.class);

    public FileProcessMain() {
    }

    public static void main(String[] args) {
        SpringApplication.run(FileProcessMain.class, args);
    }

    @Override
    public void run(String... args) {

        try {
            //Config config = readConfiguration();
            Options options = createOptions();
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            boolean cmdOption = cmd.hasOption("t");

            if (cmdOption) {
                String cmdValue = cmd.getOptionValue("t");

                if ("encrypt".equalsIgnoreCase(cmdValue)) {
                    String input = IOUtils.toString(new FileReader(cmd.getOptionValue("infile")));
                    byte[] key;
                    if (cmd.hasOption("key")) {
                        HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                        key = hashService.hash(cmd.getOptionValue("key"));
                    } else if (cmd.hasOption("keyfile")) {
                        key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(cmd.getOptionValue("keyfile"))));
                    } else {
                        throw new FileProcessRuntimeException(StatusCode.INVALID_PARAM, "Please provide -key or -keyfile");
                    }
                    CryptoSymService cryptoService = CryptoSymServiceFactory.getInstance();
                    String cipher = cryptoService.encrypt(input, key);
                    FileOutputStream output = new FileOutputStream(cmd.getOptionValue("outfile"));
                    IOUtils.write(cipher.getBytes("UTF-8"), output);
                } else if ("decrypt".equalsIgnoreCase(cmdValue)) {
                    String input = IOUtils.toString(new FileReader(cmd.getOptionValue("infile")));
                    byte[] key;
                    if (cmd.hasOption("key")) {
                        HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                        key = hashService.hash(cmd.getOptionValue("key"));
                    } else if (cmd.hasOption("keyfile")) {
                        key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(cmd.getOptionValue("keyfile"))));
                    } else {
                        throw new FileProcessRuntimeException(StatusCode.INVALID_PARAM, "Please provide -key or -keyfile");
                    }
                    CryptoSymService cryptoService = CryptoSymServiceFactory.getInstance();
                    String plain = cryptoService.decrypt(input, key);
                    FileOutputStream output = new FileOutputStream(cmd.getOptionValue("outfile"));
                    IOUtils.write(plain.getBytes("UTF-8"), output);
                } else if ("sha256".equalsIgnoreCase(cmdValue)) {
                    // Can be generated using: echo -n foobar | openssl dgst -binary -sha256 | openssl base64 | tr -d '\n' > key.txt
                    String password = cmd.getOptionValue("key");
                    HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                    byte[] key = hashService.hash(password);
                    FileOutputStream output = new FileOutputStream(cmd.getOptionValue("outfile"));
                    logger.debug("Hex: {}", Hex.encodeHexString(key));
                    IOUtils.write(Base64.getEncoder().encode(key), output);
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            logger.error(e.getMessage(), e);
        }
    }

    private Options createOptions() {
        Options options = new Options();

        options.addOption("t", true, "Target command to execute");
        options.addOption("infile", true, "Input file");
        options.addOption("outfile", true, "Output file");
        options.addOption("keyfile", true, "Key file");
        options.addOption("key", true, "Key password");
        return options;
    }

    private Config readConfiguration() {
        Config config = null;

        // Config directory
        File dir = new File(".fileprocess");
        boolean dirExists = dir.exists();
        if (dirExists) {
            logger.debug("Config directory found: {}", dir.getAbsoluteFile());
        } else {
            logger.debug("Creating config directory");
            boolean mkdirs = dir.mkdirs();
            logger.debug("Config directory created: {} => {}", mkdirs, dir.getAbsoluteFile());
        }

        // Config file
        logger.debug("Config directory: {}", dir.getAbsolutePath());
        File file = new File(dir, "config.yaml");
        boolean fileExists = file.exists();
        if (fileExists) {
            logger.debug("Config file found: {}", file);
        } else {
            logger.debug("Creating config file");
            try {
                boolean newFile = file.createNewFile();
                logger.debug("Config file created: {} => {}", newFile, file);
            } catch (IOException e) {
                logger.error("Unable to create config file", e);
            }
        }

        try {
            FileInputStream fis = new FileInputStream(file);

            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);

            Yaml yaml = new Yaml(options);
            config = yaml.loadAs(fis, Config.class);
            String keyFilePath = null, inputFilePath = null, outputFilePath = null;
            if (config != null) {
                keyFilePath = config.getKeyFilePath();
                logger.debug("Key file path: {}", keyFilePath);
                inputFilePath = config.getInputFilePath();
                logger.debug("Input file path: {}", inputFilePath);
                outputFilePath = config.getOutputFilePath();
                logger.debug("Output file path: {}", outputFilePath);

                if (keyFilePath == null || inputFilePath == null || outputFilePath == null) {
                    System.out.println("Please provide file path for key, input and output in config file: "+ file);
                }
            } else {
                config = new Config();
                config.setKeyFilePath("key.txt");
                config.setInputFilePath("input.txt");
                config.setOutputFilePath("output.txt");
            }

            // Write config file
            FileWriter writer = new FileWriter(file);
            yaml.dump(config, writer);

        } catch (FileNotFoundException e) {
            logger.error("Unable to read config file", e);
        } catch (IOException e) {
            logger.error("Unable to write config file skeleton", e);
        }
        return config;

    }
}
