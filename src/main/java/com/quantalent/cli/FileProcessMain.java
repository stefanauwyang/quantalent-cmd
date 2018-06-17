package com.quantalent.cli;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

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
        logger.debug("Running with args: {}", args);
    }
}
