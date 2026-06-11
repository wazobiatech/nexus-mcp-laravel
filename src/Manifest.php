<?php

namespace Wazobia\NexusMcp;

/**
 * Service manifest — aligned with nexus-mcp-contract manifest.schema.json.
 *
 * Serialized to JSON at GET /mcp/manifest (handler fields stripped).
 */
class Manifest
{
    /**
     * @param string          $name        Service name e.g. "muse"
     * @param string          $namespace   Lowercase namespace e.g. "muse" (used to prefix tool names)
     * @param string          $version     SemVer string e.g. "1.0.0"
     * @param string          $description Short service description
     * @param ManifestContext $context     DDD context metadata
     * @param McpToolDefinition[] $tools   Tool definitions (handlers excluded from output)
     */
    public function __construct(
        public readonly string $name,
        public readonly string $namespace,
        public readonly string $version,
        public readonly string $description,
        public readonly ManifestContext $context,
        public readonly array $tools = [],
    ) {}

    /**
     * Serialize to manifest-safe array (tool handlers excluded).
     */
    public function toArray(): array
    {
        return [
            'name'        => $this->name,
            'namespace'   => $this->namespace,
            'version'     => $this->version,
            'description' => $this->description,
            'context'     => $this->context->toArray(),
            'tools'       => array_map(
                fn (McpToolDefinition $t) => $t->toManifestArray(),
                $this->tools,
            ),
        ];
    }
}
