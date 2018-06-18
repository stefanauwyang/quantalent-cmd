package com.quantalent.cli.cmd.exception;

import com.quantalent.commons.ErrorCode;
import com.quantalent.commons.exception.BaseRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileProcessRuntimeException extends BaseRuntimeException {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessRuntimeException.class);

    public FileProcessRuntimeException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public FileProcessRuntimeException(ErrorCode errorCode, String message, Throwable e) {
        super(errorCode, message, e);
    }
}
