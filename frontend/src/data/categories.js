// Plain-language descriptions of the nine threat categories in the API
// contract. They explain the category names only; they are not findings.

export const CATEGORIES = {
  secret_access: {
    label: 'Secret access',
    description: 'Reads or embeds credentials, keys, or tokens.',
  },
  data_exfiltration: {
    label: 'Data exfiltration',
    description: 'Moves sensitive data to a network destination.',
  },
  destructive_command: {
    label: 'Destructive command',
    description: 'Deletes or overwrites files, disks, or data.',
  },
  persistence_or_privesc: {
    label: 'Persistence / privilege escalation',
    description: 'Installs startup hooks or raises privileges.',
  },
  obfuscated_execution: {
    label: 'Obfuscated or dynamic execution',
    description: 'Runs code or commands that are built at runtime.',
  },
  dependency_risk: {
    label: 'Dependency risk',
    description: 'Installs packages or fetches code from untrusted sources.',
  },
  resource_exhaustion: {
    label: 'Resource exhaustion',
    description: 'Consumes unbounded CPU, memory, disk, or processes.',
  },
  ssrf_network_exfil: {
    label: 'SSRF / network exfiltration',
    description: 'Reaches internal or metadata endpoints.',
  },
  ai_targeted_instructions: {
    label: 'AI-targeted instructions',
    description: 'Text that tries to steer an AI reviewer or agent.',
  },
}

export function categoryInfo(id) {
  return (
    CATEGORIES[id] ?? {
      label: id,
      description: 'Category reported by the backend.',
    }
  )
}
