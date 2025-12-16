package com.security.sqli.core.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for extracting and injecting parameters in JSON payloads.
 */
public class JsonParameterExtractor {
    private static final Logger logger = LoggerFactory.getLogger(JsonParameterExtractor.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Extracts all string parameters from a JSON body.
     *
     * @param jsonBody JSON string
     * @return Map of parameter paths to values
     */
    public static Map<String, String> extractParameters(String jsonBody) {
        Map<String, String> parameters = new HashMap<>();

        try {
            JsonNode root = objectMapper.readTree(jsonBody);
            extractParametersRecursive(root, "", parameters);
        } catch (Exception e) {
            logger.error("Failed to parse JSON: {}", e.getMessage());
        }

        return parameters;
    }

    /**
     * Recursively extracts parameters from JSON nodes.
     */
    private static void extractParametersRecursive(JsonNode node, String path,
                                                   Map<String, String> parameters) {
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String newPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                extractParametersRecursive(entry.getValue(), newPath, parameters);
            });
        } else if (node.isArray()) {
            int index = 0;
            for (JsonNode item : node) {
                String newPath = path + "[" + index + "]";
                extractParametersRecursive(item, newPath, parameters);
                index++;
            }
        } else if (node.isTextual() || node.isNumber()) {
            parameters.put(path, node.asText());
        }
    }

    /**
     * Injects a payload into a specific parameter in JSON.
     *
     * @param jsonBody Original JSON string
     * @param parameterPath Path to parameter (e.g., "user.name" or "items[0].id")
     * @param payload Payload to inject
     * @return Modified JSON string
     */
    public static String injectPayload(String jsonBody, String parameterPath, String payload) {
        try {
            JsonNode root = objectMapper.readTree(jsonBody);
            JsonNode modified = injectPayloadRecursive(root, parameterPath, payload);
            return objectMapper.writeValueAsString(modified);
        } catch (Exception e) {
            logger.error("Failed to inject payload into JSON: {}", e.getMessage());
            return jsonBody;
        }
    }

    /**
     * Recursively injects payload into JSON.
     */
    private static JsonNode injectPayloadRecursive(JsonNode node, String path, String payload) {
        if (path.isEmpty()) {
            return objectMapper.valueToTree(payload);
        }

        if (path.contains(".")) {
            // Navigate to nested object
            String[] parts = path.split("\\.", 2);
            String currentKey = parts[0];
            String remainingPath = parts[1];

            if (node.isObject()) {
                ObjectNode objectNode = (ObjectNode) node;
                JsonNode childNode = objectNode.get(currentKey);

                if (childNode != null) {
                    JsonNode modified = injectPayloadRecursive(childNode, remainingPath, payload);
                    objectNode.set(currentKey, modified);
                }
            }
        } else if (path.matches(".*\\[\\d+\\]$")) {
            // Handle array access
            String key = path.substring(0, path.indexOf("["));
            int index = Integer.parseInt(path.substring(path.indexOf("[") + 1, path.indexOf("]")));

            if (node.isObject()) {
                ObjectNode objectNode = (ObjectNode) node;
                JsonNode arrayNode = objectNode.get(key);

                if (arrayNode != null && arrayNode.isArray() && index < arrayNode.size()) {
                    ((ArrayNode) arrayNode).set(index, objectMapper.valueToTree(payload));
                }
            }
        } else {
            // Direct property
            if (node.isObject()) {
                ((ObjectNode) node).put(path, payload);
            }
        }

        return node;
    }

    /**
     * Gets all injectable parameter paths from JSON.
     *
     * @param jsonBody JSON string
     * @return List of parameter paths
     */
    public static List<String> getParameterPaths(String jsonBody) {
        return new ArrayList<>(extractParameters(jsonBody).keySet());
    }

    /**
     * Validates if a string is valid JSON.
     *
     * @param jsonString String to validate
     * @return True if valid JSON, false otherwise
     */
    public static boolean isValidJson(String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return false;
        }

        try {
            objectMapper.readTree(jsonString);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
