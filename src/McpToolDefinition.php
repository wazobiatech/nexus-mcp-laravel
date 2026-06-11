<?php

namespace Wazobia\NexusMcp;

/**
 * Defines a single tool exposed through the Nexus MCP ecosystem.
 *
 * Usage:
 *
 *   new McpToolDefinition(
 *       name: 'muse__get_posts',
 *       description: 'Retrieve a paginated list of blog posts for a tenant.',
 *       inputSchema: [
 *           'type' => 'object',
 *           'properties' => [
 *               'limit'  => ['type' => 'integer', 'default' => 10],
 *               'offset' => ['type' => 'integer', 'default' => 0],
 *               'x_user_token' => ['type' => 'string'],
 *           ],
 *       ],
 *       handler: function (array $args): array {
 *           // Call your service here
 *           return PostService::list($args);
 *       },
 *   )
 */
class McpToolDefinition
{
    /**
     * @param string        $name        Snake-case tool name (e.g. muse__get_posts)
     * @param string        $description Human-readable description (min 20 chars)
     * @param array         $inputSchema JSON Schema object describing input arguments
     * @param mixed|null    $handler     Callable invoked at tool-call time.
     *                                   Receives array $args, returns array|mixed.
     *                                   NOT serialized to the manifest.
     *                                   PHP does not allow `callable` as a property type;
     *                                   typed as `mixed` to allow any callable value.
     * @param array|null    $annotations Optional behavioural hints (readOnly, destructive)
     */
    public function __construct(
        public readonly string $name,
        public readonly string $description,
        public readonly array $inputSchema,
        public readonly mixed $handler = null,
        public readonly ?array $annotations = null,
    ) {}

    /**
     * Serialize to manifest-safe array (handler excluded).
     */
    public function toManifestArray(): array
    {
        $tool = [
            'name'        => $this->name,
            'description' => $this->description,
            'inputSchema' => $this->inputSchema,
        ];

        if ($this->annotations !== null) {
            $tool['annotations'] = $this->annotations;
        }

        return $tool;
    }
}
