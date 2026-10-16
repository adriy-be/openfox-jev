import { createReviewer, readConfig, MODES } from './reviewer.js'
import { createAuditLog } from './audit.js'
import { DEFAULT_MODEL, LOCAL_DEFAULT_URL, BACKEND_KINDS, isRemoteBackend } from './providers.js'
import { QUESTIONS } from './client.js'
import { POLICY_VERSION } from './policy.js'

function localized(enText, frText) {
  return { en: enText, fr: frText }
}

const SETTINGS_FIELDS = [
  // ── General ─────────────────────────────────────────────────────────────
  {
    key: 'enabled',
    type: 'boolean',
    section: localized('General', 'Général'),
    label: localized('Enable smart approvals', 'Activer les approbations intelligentes'),
    description: localized(
      'When off, OpenFox behaves exactly as before (native confirmations only).',
      'Désactivé, OpenFox se comporte exactement comme avant (confirmations natives uniquement).',
    ),
    default: false,
  },
  {
    key: 'mode',
    type: 'select',
    section: localized('General', 'Général'),
    label: localized('Mode', 'Mode'),
    description: localized(
      'Shadow: assess and record predictions without changing approvals. Enforce: model decisions apply within the approval policy.',
      'Shadow : évalue et enregistre les prédictions sans modifier les approbations. Enforce : les décisions du modèle s’appliquent selon la politique.',
    ),
    options: [
      { value: 'shadow', label: localized('Shadow', 'Shadow') },
      { value: 'enforce', label: localized('Enforce', 'Enforce') },
    ],
    default: 'shadow',
  },
  {
    key: 'timeoutMs',
    type: 'number',
    section: localized('General', 'Général'),
    label: localized('Approval timeout (ms)', 'Délai d’approbation (ms)'),
    description: localized(
      'Backend requests that exceed this timeout escalate to manual confirmation.',
      'Les requêtes backend dépassant ce délai passent en confirmation manuelle.',
    ),
    default: 15000,
  },

  // ── Model ───────────────────────────────────────────────────────────────
  {
    key: 'providerId',
    type: 'select',
    section: localized('Model', 'Modèle'),
    label: localized('Decision provider (from Provider Manager)', 'Fournisseur de décision (depuis le Provider Manager)'),
    description: localized(
      'Select an already configured OpenFox provider. No API key is ever entered here.',
      'Sélectionnez un fournisseur OpenFox déjà configuré. Aucune clé API n’est saisie ici.',
    ),
    optionsFrom: 'providers',
    options: [],
    default: '',
  },
  {
    key: 'backendKind',
    type: 'select',
    section: localized('Model', 'Modèle'),
    label: localized('Backend type', 'Type de backend'),
    description: localized(
      'Auto follows the selected provider’s verified origin. Custom requires an explicit HTTPS endpoint.',
      'Auto suit l’origine vérifiée du fournisseur sélectionné. Custom exige un point de terminaison HTTPS explicite.',
    ),
    options: [
      { value: '', label: localized('Auto (from provider)', 'Auto (depuis le fournisseur)') },
      { value: 'local', label: localized('Local Jev-Style', 'Jev-Style local') },
      { value: 'openrouter', label: localized('OpenRouter decisions', 'Décisions OpenRouter') },
      { value: 'deepinfra', label: localized('DeepInfra decisions', 'Décisions DeepInfra') },
      { value: 'custom', label: localized('Custom compatible endpoint', 'Point de terminaison compatible personnalisé') },
    ],
    default: '',
  },
  {
    key: 'model',
    type: 'text',
    section: localized('Model', 'Modèle'),
    label: localized('Decision model', 'Modèle de décision'),
    description: localized(
      `Default: ${DEFAULT_MODEL}. Local Jev servers ignore this field.`,
      `Par défaut : ${DEFAULT_MODEL}. Les serveurs Jev locaux ignorent ce champ.`,
    ),
    default: '',
    placeholder: DEFAULT_MODEL,
  },
  {
    key: 'localUrl',
    type: 'text',
    section: localized('Model', 'Modèle'),
    label: localized('Local Jev URL', 'URL Jev locale'),
    description: localized(
      'Loopback only (127.0.0.1/localhost). The Jev server is started and managed independently — this plugin never starts a GPU workload.',
      'Boucle locale uniquement (127.0.0.1/localhost). Le serveur Jev est démarré et géré indépendamment — ce plugin ne lance jamais de charge GPU.',
    ),
    default: LOCAL_DEFAULT_URL,
    placeholder: LOCAL_DEFAULT_URL,
  },
  {
    key: 'localApiKey',
    type: 'password',
    secret: true,
    section: localized('Model', 'Modèle'),
    label: localized('Local Jev API key (optional)', 'Clé API Jev locale (facultatif)'),
    description: localized(
      'Only used for a local server started with --api-key-env. Never sent anywhere but loopback.',
      'Utilisée uniquement avec un serveur local démarré avec --api-key-env. Jamais envoyée ailleurs qu’en boucle locale.',
    ),
    default: '',
  },
  {
    key: 'customEndpoint',
    type: 'text',
    section: localized('Model', 'Modèle'),
    label: localized('Custom endpoint (custom backend only)', 'Point de terminaison personnalisé (backend custom uniquement)'),
    description: localized(
      'HTTPS required unless loopback. Used only when Backend type = Custom.',
      'HTTPS requis sauf boucle locale. Utilisé uniquement si le type de backend = Custom.',
    ),
    default: '',
  },
  {
    key: 'testConnection',
    type: 'button',
    section: localized('Model', 'Modèle'),
    label: localized('Connection test', 'Test de connexion'),
    buttonLabel: localized('Test connection', 'Tester la connexion'),
    rpcMethod: 'testConnection',
  },
  {
    key: 'connectionStatus',
    type: 'status',
    section: localized('Model', 'Modèle'),
    label: localized('Connection status', 'Statut de connexion'),
    rpcMethod: 'connectionStatus',
  },

  // ── Approval policy ─────────────────────────────────────────────────────
  {
    key: 'operatorPolicy',
    type: 'textarea',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Operator policy', 'Politique de l’opérateur'),
    description: localized(
      'Trusted instructions for the decision model, e.g. "Routine read-only git commands are allowed."',
      'Instructions de confiance pour le modèle de décision, p. ex. « Les commandes git en lecture seule sont autorisées. »',
    ),
    default: '',
  },
  {
    key: 'minApprovalProbability',
    type: 'number',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Minimum approval probability (0-1)', 'Probabilité d’approbation minimale (0-1)'),
    default: 0.85,
  },
  {
    key: 'minConfidence',
    type: 'number',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Minimum model confidence (0-1)', 'Confiance minimale du modèle (0-1)'),
    default: 0.55,
  },
  {
    key: 'escalateBlastRadius',
    type: 'number',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Escalate at blast radius ≥ (0-4)', 'Escalader si rayon d’impact ≥ (0-4)'),
    default: 1.6,
  },
  {
    key: 'maxBlastRadius',
    type: 'number',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Hard-escalate at blast radius ≥ (0-4)', 'Escalade stricte si rayon d’impact ≥ (0-4)'),
    default: 2.0,
  },
  {
    key: 'auditEnabled',
    type: 'boolean',
    section: localized('Approval policy', 'Politique d’approbation'),
    label: localized('Audit logging', 'Journalisation d’audit'),
    description: localized(
      'Structured JSONL records with redacted/hashed operations. Logging failures never change decisions.',
      'Enregistrements JSONL structurés avec opérations rédigées/hachées. Les échecs de journalisation ne changent jamais les décisions.',
    ),
    default: true,
  },

  // ── Privacy ─────────────────────────────────────────────────────────────
  {
    key: 'cloudConsent',
    type: 'boolean',
    section: localized('Privacy', 'Confidentialité'),
    label: localized('Permit sending approval data to a cloud provider', 'Autoriser l’envoi de données d’approbation à un fournisseur cloud'),
    description: localized(
      'Required for OpenRouter/DeepInfra, including in shadow mode. Local Jev-Style inference never needs this. Operation data is redacted before sending; secrets are never logged.',
      'Requis pour OpenRouter/DeepInfra, y compris en mode shadow. L’inférence Jev-Style locale n’en a jamais besoin. Les données d’opération sont rédigées avant envoi ; les secrets ne sont jamais journalisés.',
    ),
    default: false,
  },
]

export function register(registry) {
  const context = registry.context
  const audit = createAuditLog({ enabled: true })

  const getSettings = () => ({
    ...context.settings('global'),
    ...(context.settings('project') ?? {}),
  })

  const reviewer = createReviewer({
    getSettings,
    providerAccess: context.providerAccess,
    audit,
  })

  registry.registerSettings({ fields: SETTINGS_FIELDS })

  registry.registerApprovalReviewer({
    id: 'openfox-jev',
    evaluate: (approvalContext) => reviewer.evaluate(approvalContext),
  })

  registry.registerRpc('testConnection', async () => {
    const config = readConfig(getSettings())
    if (!config.enabled) {
      return { installed: true, running: false, statusTone: 'warning', statusText: localized('Disabled', 'Désactivé') }
    }
    if (!config.providerId || !context.providerAccess) {
      return { installed: true, running: false, statusTone: 'danger', statusText: localized('No provider selected', 'Aucun fournisseur sélectionné') }
    }
    const provider = context.providerAccess.getProvider(config.providerId)
    if (!provider) {
      return { installed: true, running: false, statusTone: 'danger', statusText: localized('Provider not found', 'Fournisseur introuvable') }
    }
    const remote = ['openrouter', 'deepinfra', 'custom'].includes(config.backendKind || '')
    if (remote && !config.cloudConsent) {
      return { installed: true, running: false, statusTone: 'warning', statusText: localized('Cloud consent required', 'Consentement cloud requis') }
    }
    const started = Date.now()
    try {
      const result = await reviewer.evaluate({
        kind: 'command',
        tool: 'connection_test',
        description: 'git status',
        workdir: '/',
        sessionId: 'connection-test',
      })
      const latency = Date.now() - started
      return {
        installed: true,
        running: true,
        statusTone: 'success',
        statusText: localized(
          `${provider.name} · ${config.model || DEFAULT_MODEL} · ${config.mode} · ${latency} ms · ${result.meta?.decision ?? 'OK'}`,
          `${provider.name} · ${config.model || DEFAULT_MODEL} · ${config.mode} · ${latency} ms · ${result.meta?.decision ?? 'OK'}`,
        ),
      }
    } catch (error) {
      return {
        installed: true,
        running: false,
        statusTone: 'danger',
        statusText: localized(
          `Connection failed: ${error instanceof Error ? error.message : String(error)}`,
          `Échec de la connexion : ${error instanceof Error ? error.message : String(error)}`,
        ),
      }
    }
  })

  registry.registerRpc('connectionStatus', async () => {
    const config = readConfig(getSettings())
    if (!config.enabled) {
      return { installed: true, running: false, statusTone: 'warning', statusText: localized('Disabled', 'Désactivé') }
    }
    const provider = config.providerId && context.providerAccess ? context.providerAccess.getProvider(config.providerId) : undefined
    const remote = provider ? isRemoteBackend(provider, { backendKind: config.backendKind || undefined }) : config.backendKind !== 'local'
    if (remote && !config.cloudConsent) {
      return { installed: true, running: false, statusTone: 'warning', statusText: localized('Cloud consent required', 'Consentement cloud requis') }
    }
    if (!provider && config.backendKind !== 'local') {
      return { installed: true, running: false, statusTone: 'danger', statusText: localized('No provider selected', 'Aucun fournisseur sélectionné') }
    }
    return {
      installed: true,
      running: true,
      statusTone: 'success',
      statusText: localized(
        `${provider?.name ?? 'Local Jev-Style'} · ${config.model || DEFAULT_MODEL} · ${config.mode}`,
        `${provider?.name ?? 'Jev-Style local'} · ${config.model || DEFAULT_MODEL} · ${config.mode}`,
      ),
    }
  })

  registry.registerRpc('listBackends', () => ({
    kinds: BACKEND_KINDS,
    modes: MODES,
    questions: QUESTIONS,
    policyVersion: POLICY_VERSION,
  }))
}

export { SETTINGS_FIELDS }