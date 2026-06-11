<?php

namespace Wazobia\NexusMcp;

/**
 * DDD context metadata embedded in the service manifest.
 */
class ManifestContext
{
    /**
     * @param string   $domain         Short domain label e.g. "Blog & Content"
     * @param string   $purpose        Why this service exists
     * @param string   $boundedContext What this service owns (and does not own)
     * @param string[] $keyEntities    Domain entity names
     * @param string[] $aggregates     Aggregate root names
     */
    public function __construct(
        public readonly string $domain,
        public readonly string $purpose,
        public readonly string $boundedContext,
        public readonly array $keyEntities = [],
        public readonly array $aggregates = [],
    ) {}

    public function toArray(): array
    {
        return [
            'domain'          => $this->domain,
            'purpose'         => $this->purpose,
            'bounded_context' => $this->boundedContext,
            'key_entities'    => $this->keyEntities,
            'aggregates'      => $this->aggregates,
        ];
    }
}
