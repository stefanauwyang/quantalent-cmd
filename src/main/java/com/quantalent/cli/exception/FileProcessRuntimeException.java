package com.quantalent.cli.exception;

import com.quantalent.commons.StatusCode;
import com.quantalent.commons.exception.BaseRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileProcessRuntimeException extends BaseRuntimeException {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessRuntimeException.class);

    public FileProcessRuntimeException(StatusCode statusCode, String message) {
        super(statusCode, message);
    }

    public FileProcessRuntimeException(StatusCode statusCode, String message, Throwable e) {
        super(statusCode, message, e);
    }
}
