package com.quantalent.cli.cmd;

import com.quantalent.cli.cmd.model.Config;
import com.quantalent.crypto.CryptoSymService;
import com.quantalent.crypto.HashService;
import com.quantalent.crypto.hash.HashServiceFactory;
import com.quantalent.crypto.model.Algorithm;
import com.quantalent.crypto.sym.CryptoSymServiceFactory;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.util.Base64;
import java.util.Scanner;

public class CmdRunner implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(CmdRunner.class);

    @Override
    public void run(String... args) {
        try {
            Options options = createOptions();
            Config config = readConfiguration();

            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("encrypt")) {
                byte[] input;
                if (cmd.hasOption("infile")) {
                    logger.info("Using infile parameter: {}", cmd.getOptionValue("infile"));
                    input = IOUtils.toByteArray(new FileInputStream(cmd.getOptionValue("infile")));
                } else {
                    logger.info("Using inputFilePath config: {}", config.getInputFilePath());
                    input = IOUtils.toByteArray(new FileInputStream(config.getInputFilePath()));
                }
                byte[] key;
                if (cmd.hasOption("key")) {
                    logger.info("Using key parameter");
                    HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                    key = hashService.hash(cmd.getOptionValue("key"));
                } else if (cmd.hasOption("keyfile")) {
                    logger.info("Using keyfile parameter: {}", cmd.getOptionValue("keyfile"));
                    key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(cmd.getOptionValue("keyfile"))));
                } else if (config.getKeyFilePath() != null) {
                    logger.info("Using keyFilePath config: {}", config.getKeyFilePath());
                    key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(config.getKeyFilePath())));
                } else {
                    logger.info("Asking for password key...");
                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Password as key: ");
                    String password = scanner.nextLine();
                    logger.info("Hashing password...");
                    HashService hashService = HashServiceFactory.getInstance();
                    key = hashService.hash(password);
                }
                CryptoSymService cryptoService = CryptoSymServiceFactory.getInstance();
                String cipher = cryptoService.encrypt(input, key);

                FileOutputStream output;
                if (cmd.hasOption("outfile")) {
                    logger.info("Using outfile parameter: {}", cmd.getOptionValue("outfile"));
                    output = new FileOutputStream(cmd.getOptionValue("outfile"));
                } else {
                    logger.info("Using outputFilePath config: {}", config.getOutputFilePath());
                    output = new FileOutputStream(config.getOutputFilePath());
                }
                IOUtils.write(cipher.getBytes("UTF-8"), output);
                output.close();
                logger.info("Finish writing to output");
            } else if (cmd.hasOption("decrypt")) {
                String input;
                if (cmd.hasOption("infile")) {
                    logger.info("Using infile parameter: {}", cmd.getOptionValue("infile"));
                    input = IOUtils.toString(new FileReader(cmd.getOptionValue("infile")));
                } else {
                    logger.info("Using inputFilePath config: {}", config.getInputFilePath());
                    input = IOUtils.toString(new FileReader(config.getInputFilePath()));
                }
                byte[] key;
                if (cmd.hasOption("key")) {
                    logger.info("Using key parameter");
                    HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                    key = hashService.hash(cmd.getOptionValue("key"));
                } else if (cmd.hasOption("keyfile")) {
                    logger.info("Using keyfile parameter: {}", cmd.getOptionValue("keyfile"));
                    key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(cmd.getOptionValue("keyfile"))));
                } else if (config.getKeyFilePath() != null) {
                    logger.info("Using keyFilePath config: {}", config.getKeyFilePath());
                    key = Base64.getDecoder().decode(IOUtils.toByteArray(new FileInputStream(config.getKeyFilePath())));
                } else {
                    logger.info("Asking for password key...");
                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Password as key: ");
                    String password = scanner.nextLine();
                    logger.info("Hashing password...");
                    HashService hashService = HashServiceFactory.getInstance();
                    key = hashService.hash(password);
                }
                CryptoSymService cryptoService = CryptoSymServiceFactory.getInstance();
                byte[] plain = cryptoService.decrypt(input, key);
                FileOutputStream output;
                if (cmd.hasOption("outfile")) {
                    logger.info("Using outfile parameter: {}", cmd.getOptionValue("outfile"));
                    output = new FileOutputStream(cmd.getOptionValue("outfile"));
                } else {
                    logger.info("Using outputFilePath config: {}", config.getOutputFilePath());
                    output = new FileOutputStream(config.getOutputFilePath());
                }
                IOUtils.write(plain, output);
                output.close();
                logger.info("Finish writing to output");
            } else if (cmd.hasOption("sha256")) {
                // Can be generated using: echo -n foobar | openssl dgst -binary -sha256 | openssl base64 | tr -d '\n' > key.txt
                String password = cmd.getOptionValue("key");
                HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
                byte[] key = hashService.hash(password);
                FileOutputStream output;
                if (cmd.hasOption("outfile")) {
                    output = new FileOutputStream(cmd.getOptionValue("outfile"));
                } else {
                    output = new FileOutputStream(config.getOutputFilePath());
                }
                logger.debug("Hex: {}", Hex.encodeHexString(key));
                IOUtils.write(Base64.getEncoder().encode(key), output);
                output.close();
                logger.info("Finish writing to output");
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private Options createOptions() {
        Options options = new Options();

        options.addOption("encrypt", false, "Encrypt command");
        options.addOption("decrypt", false, "Decrypt command");
        options.addOption("sha256", false, "Sha256 command");
        options.addOption("infile", true, "Input file");
        options.addOption("outfile", true, "Output file");
        options.addOption("keyfile", true, "Key file");
        options.addOption("key", true, "Key password");
        return options;
    }

    private Config readConfiguration() {
        Config config = null;

        // Config directory
        File dir = new File(".cmd");
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
        File file = new File(dir, "config.yml");
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
            String keyFilePath = ".cmd/key.txt", inputFilePath = ".cmd/input.txt", outputFilePath = ".cmd/output.txt";
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
                config.setKeyFilePath(".cmd/key.txt");
                config.setInputFilePath(".cmd/input.txt");
                config.setOutputFilePath(".cmd/output.txt");
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
