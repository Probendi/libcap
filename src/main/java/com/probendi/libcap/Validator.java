package com.probendi.libcap;

import java.util.logging.Logger;

import org.jetbrains.annotations.Contract;

/**
 * Validates the input.
 *
 * @author Daniele Di Salvo
 * @since 1.0
 */
public class Validator {

    private static final Logger logger = Logger.getLogger(Validator.class.getName());

    /**
     * Validates the given object.
     *
     * @param name  the variable's name
     * @param value the value to be validated
     * @throws IllegalArgumentException if {@code value} is {@code null}
     */
    @Contract("_, null -> fail")
    public static void validateObject(final String name, final Object value) {
        if (value == null) {
            final IllegalArgumentException e = new IllegalArgumentException(name + " is not set");
            logger.throwing(Validator.class.getName(), "validateObject", e);
            throw e;
        }
    }
}
