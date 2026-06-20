// FIREALIVE -- SDN segmentation-policy generator (B5i SDN Mode)
//
// Pure, side-effect-free generator. It translates the operator-declared
// tier_segment_map (FireAlive tier / component -> network segment) into a
// default-deny, least-privilege micro-segmentation policy and renders it in the
// native construct vocabulary of each supported SDN platform.
//
// The output is an ADVISORY artifact: the operator reviews it and implements it
// through their own change-control process. FireAlive is read-only toward every
// controller and never applies, pushes, or programs any policy. This module
// touches no database and makes no network call.
//
// Security posture (fixed, not configurable):
//   - default-deny baseline: every east-west flow is denied unless explicitly
//     allowed;
//   - least-privilege allow-set: only FireAlive's known-required component
//     flows are permitted (REQUIRED_FLOWS);
//   - structural privacy at L3/L4: management / aggregate zones (Tier-1) are
//     never permitted to reach analyst-private zones (Tier-3). No such flow
//     exists in REQUIRED_FLOWS, so no allow targeting a private zone from a
//     management zone can be emitted on any platform; the deny is also asserted
//     explicitly whenever both sides are declared.
//
// Ports in REQUIRED_FLOWS are documented defaults the operator confirms against
// their deployment; the artifact says so.
//
// ASCII only; no template literals.

function fail(code, message) {
  var e = new Error(message);
  e.code = code;
  return e;
}

var SUPPORTED_PLATFORMS = [
  'cisco-aci', 'vmware-nsx', 'openflow', 'arista-cv',
  'juniper-cn2', 'calico', 'cilium', 'custom'
];

// Canonical FireAlive component roles and tolerant aliases for operator labels.
var ROLE_ALIASES = {
  'analyst-client': 'analyst-client', 'analyst': 'analyst-client', 'ac': 'analyst-client', 'analyst-private': 'analyst-client',
  'management-console': 'management-console', 'management': 'management-console', 'mc': 'management-console', 'console': 'management-console',
  'regional-server': 'regional-server', 'regional': 'regional-server', 'rs': 'regional-server',
  'global-dashboard': 'global-dashboard', 'dashboard': 'global-dashboard', 'gd': 'global-dashboard',
  'gd-server': 'gd-server', 'gdserver': 'gd-server', 'gds': 'gd-server', 'global-dashboard-server': 'gd-server'
};

// Documented default ports (operator-confirmable). FireAlive components speak
// HTTPS; the artifact instructs the operator to confirm against their ports.
var DEFAULT_API_PORT = 443;  // Regional Server HTTPS API
var DEFAULT_GD_PORT = 443;   // GD-Server HTTPS ingest

// FireAlive's minimal required east-west flows (least privilege). By
// construction this set contains NO flow whose destination is the analyst
// (private) role, which is what makes management -> analyst-private
// unrepresentable in any rendering.
var REQUIRED_FLOWS = [
  { from: 'analyst-client',     to: 'regional-server', protocol: 'tcp', port: DEFAULT_API_PORT, purpose: 'Analyst Client to Regional Server API (E2EE application traffic)' },
  { from: 'management-console', to: 'regional-server', protocol: 'tcp', port: DEFAULT_API_PORT, purpose: 'Management Console to Regional Server API (Tier-1 aggregates only)' },
  { from: 'regional-server',    to: 'gd-server',       protocol: 'tcp', port: DEFAULT_GD_PORT,  purpose: 'Regional Server aggregate push to GD-Server (Tier-1 only)' },
  { from: 'global-dashboard',   to: 'gd-server',       protocol: 'tcp', port: DEFAULT_GD_PORT,  purpose: 'Global Dashboard read from GD-Server (Tier-1 aggregates)' }
];

var MANAGEMENT_ROLES = ['management-console', 'global-dashboard', 'gd-server'];
var PRIVATE_ROLES = ['analyst-client'];

var ADVISORY_TEXT =
  'RECOMMENDED segmentation policy generated from the FireAlive network map. ' +
  'Review it against your deployment and implement it through your own ' +
  'change-control process. FireAlive is read-only toward your controller and ' +
  'does not apply, push, or program this policy. Confirm all ports against ' +
  'your deployment before use.';

var STRUCTURAL_PRIVACY_TEXT =
  'Management and aggregate zones (Tier-1: Management Console, Global ' +
  'Dashboard, GD-Server) must never reach analyst-private zones (Tier-3: ' +
  'Analyst Client). This policy never emits such an allow and asserts the ' +
  'deny explicitly.';

var BINDING_NOTE =
  'Zone selectors reference the FireAlive zone labels from your network map. ' +
  'Bind each zone to the concrete namespace, label, security group, EPG, ' +
  'address group, tag, or CIDR in your environment before applying.';

function normLabel(label) {
  return String(label == null ? '' : label).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

function slug(s) {
  var n = normLabel(s).replace(/^-+|-+$/g, '');
  return n.length ? n : 'zone';
}

function canonicalRole(label) {
  var n = normLabel(label);
  return Object.prototype.hasOwnProperty.call(ROLE_ALIASES, n) ? ROLE_ALIASES[n] : null;
}

// Sensitivity class for the structural-privacy assertion. Works for role labels
// AND tier labels (tier1/tier3). The Regional Server is the trusted data
// custodian, not a management consumer, so it is deliberately neither class.
function sensitivityOf(label) {
  var role = canonicalRole(label);
  if (PRIVATE_ROLES.indexOf(role) !== -1) return 'private';
  if (MANAGEMENT_ROLES.indexOf(role) !== -1) return 'management';
  var n = normLabel(label);
  if (n === 'tier3' || n === 'tier-3' || n === 'private' || n.indexOf('analyst-private') !== -1) return 'private';
  if (n === 'tier1' || n === 'tier-1' || n.indexOf('aggregate') !== -1) return 'management';
  return null;
}

// --- stage 1: platform-neutral model -----------------------------------------

function buildSegmentationModel(networkMap) {
  var map = networkMap || {};
  var tsm = (map.tierSegmentMap && typeof map.tierSegmentMap === 'object' && !Array.isArray(map.tierSegmentMap)) ? map.tierSegmentMap : {};
  var permitted = Array.isArray(map.permittedSegments) ? map.permittedSegments.slice() : [];

  var zones = Object.keys(tsm).map(function (label) {
    return { label: label, segment: tsm[label], role: canonicalRole(label), sensitivity: sensitivityOf(label) };
  });

  var presentSeg = {};
  var presentLabel = {};
  zones.forEach(function (z) {
    if (z.role) { presentSeg[z.role] = z.segment; presentLabel[z.role] = z.label; }
  });

  var allowedFlows = REQUIRED_FLOWS
    .filter(function (f) { return presentLabel[f.from] && presentLabel[f.to]; })
    .map(function (f) {
      return {
        from: f.from, to: f.to, protocol: f.protocol, port: f.port, purpose: f.purpose,
        fromLabel: presentLabel[f.from], toLabel: presentLabel[f.to],
        fromSegment: presentSeg[f.from], toSegment: presentSeg[f.to]
      };
    });

  // Structural-privacy denies: every management-sensitivity zone -> every
  // private-sensitivity zone, whenever both are declared.
  var assertedDenies = [];
  zones.forEach(function (a) {
    if (a.sensitivity !== 'management') return;
    zones.forEach(function (b) {
      if (b.sensitivity !== 'private') return;
      assertedDenies.push({
        fromLabel: a.label, toLabel: b.label, fromSegment: a.segment, toSegment: b.segment,
        reason: 'structural privacy: management/aggregate (Tier-1) must not reach analyst-private (Tier-3)'
      });
    });
  });

  return {
    generatedAt: new Date().toISOString(),
    sourceMapUpdatedAt: map.updatedAt || null,
    defaultDeny: true,
    zones: zones,
    permittedSegments: permitted,
    allowedFlows: allowedFlows,
    assertedDenies: assertedDenies,
    recognizedRoles: zones.filter(function (z) { return z.role; }).map(function (z) { return z.role; }),
    unrecognizedLabels: zones.filter(function (z) { return !z.role; }).map(function (z) { return z.label; })
  };
}

// --- stage 2: per-platform rendering -----------------------------------------

function advisoryHeader(platform, model) {
  return {
    generator: 'FireAlive SDN segmentation-policy generator',
    platform: platform,
    generatedAt: model.generatedAt,
    sourceNetworkMapUpdatedAt: model.sourceMapUpdatedAt,
    posture: 'default-deny',
    advisory: ADVISORY_TEXT,
    structuralPrivacy: STRUCTURAL_PRIVACY_TEXT,
    bindingNote: BINDING_NOTE
  };
}

// Canonical platform-neutral intent. Embedded in every artifact (and the whole
// rendering for 'custom') so the operator can verify the native rendering.
function canonicalIntent(model) {
  var deny = [{ rule: 'default-deny', match: 'any to any not explicitly allowed' }];
  model.assertedDenies.forEach(function (d) {
    deny.push({ from: d.fromLabel, fromSegment: d.fromSegment, to: d.toLabel, toSegment: d.toSegment, reason: d.reason });
  });
  return {
    defaultDeny: true,
    zones: model.zones.map(function (z) { return { label: z.label, segment: z.segment, role: z.role, sensitivity: z.sensitivity }; }),
    fireAliveOwnedSegments: model.permittedSegments,
    allow: model.allowedFlows.map(function (f) {
      return { from: f.from, fromSegment: f.fromSegment, to: f.to, toSegment: f.toSegment, protocol: f.protocol, port: f.port, purpose: f.purpose };
    }),
    deny: deny
  };
}

function zoneLabelFor(model, x) {
  return x; // labels are passed through directly; selectors bind firealive zone == label
}

function renderCilium(model) {
  var policies = [];
  model.zones.forEach(function (z) {
    policies.push({
      apiVersion: 'cilium.io/v2', kind: 'CiliumClusterwideNetworkPolicy',
      metadata: { name: 'firealive-default-deny-' + slug(z.label) },
      spec: { endpointSelector: { matchLabels: { 'firealive.io/zone': z.label } }, ingress: [], egress: [] }
    });
  });
  model.allowedFlows.forEach(function (f) {
    policies.push({
      apiVersion: 'cilium.io/v2', kind: 'CiliumClusterwideNetworkPolicy',
      metadata: { name: 'firealive-allow-ingress-' + slug(f.from) + '-to-' + slug(f.to) },
      spec: {
        endpointSelector: { matchLabels: { 'firealive.io/zone': f.toLabel } },
        ingress: [{
          fromEndpoints: [{ matchLabels: { 'firealive.io/zone': f.fromLabel } }],
          toPorts: [{ ports: [{ port: String(f.port), protocol: f.protocol.toUpperCase() }] }]
        }]
      }
    });
    policies.push({
      apiVersion: 'cilium.io/v2', kind: 'CiliumClusterwideNetworkPolicy',
      metadata: { name: 'firealive-allow-egress-' + slug(f.from) + '-to-' + slug(f.to) },
      spec: {
        endpointSelector: { matchLabels: { 'firealive.io/zone': f.fromLabel } },
        egress: [{
          toEndpoints: [{ matchLabels: { 'firealive.io/zone': f.toLabel } }],
          toPorts: [{ ports: [{ port: String(f.port), protocol: f.protocol.toUpperCase() }] }]
        }]
      }
    });
  });
  model.assertedDenies.forEach(function (d) {
    policies.push({
      apiVersion: 'cilium.io/v2', kind: 'CiliumClusterwideNetworkPolicy',
      metadata: { name: 'firealive-deny-' + slug(d.fromLabel) + '-to-' + slug(d.toLabel) },
      spec: {
        endpointSelector: { matchLabels: { 'firealive.io/zone': d.toLabel } },
        ingressDeny: [{ fromEndpoints: [{ matchLabels: { 'firealive.io/zone': d.fromLabel } }] }]
      }
    });
  });
  return policies;
}

function renderCalico(model) {
  var policies = [];
  model.assertedDenies.forEach(function (d, i) {
    policies.push({
      apiVersion: 'projectcalico.org/v3', kind: 'GlobalNetworkPolicy',
      metadata: { name: 'firealive-deny-' + slug(d.fromLabel) + '-to-' + slug(d.toLabel) },
      spec: {
        order: 100 + i, selector: 'firealive-zone == "' + d.toLabel + '"', types: ['Ingress'],
        ingress: [{ action: 'Deny', source: { selector: 'firealive-zone == "' + d.fromLabel + '"' } }]
      }
    });
  });
  model.allowedFlows.forEach(function (f, i) {
    policies.push({
      apiVersion: 'projectcalico.org/v3', kind: 'GlobalNetworkPolicy',
      metadata: { name: 'firealive-allow-ingress-' + slug(f.from) + '-to-' + slug(f.to) },
      spec: {
        order: 500 + i, selector: 'firealive-zone == "' + f.toLabel + '"', types: ['Ingress'],
        ingress: [{ action: 'Allow', protocol: f.protocol.toUpperCase(), source: { selector: 'firealive-zone == "' + f.fromLabel + '"' }, destination: { ports: [f.port] } }]
      }
    });
    policies.push({
      apiVersion: 'projectcalico.org/v3', kind: 'GlobalNetworkPolicy',
      metadata: { name: 'firealive-allow-egress-' + slug(f.from) + '-to-' + slug(f.to) },
      spec: {
        order: 500 + i, selector: 'firealive-zone == "' + f.fromLabel + '"', types: ['Egress'],
        egress: [{ action: 'Allow', protocol: f.protocol.toUpperCase(), destination: { selector: 'firealive-zone == "' + f.toLabel + '"', ports: [f.port] } }]
      }
    });
  });
  model.zones.forEach(function (z) {
    policies.push({
      apiVersion: 'projectcalico.org/v3', kind: 'GlobalNetworkPolicy',
      metadata: { name: 'firealive-default-deny-' + slug(z.label) },
      spec: {
        order: 2000, selector: 'firealive-zone == "' + z.label + '"', types: ['Ingress', 'Egress'],
        ingress: [{ action: 'Deny' }], egress: [{ action: 'Deny' }]
      }
    });
  });
  return policies;
}

function renderCn2(model) {
  var rules = [];
  model.assertedDenies.forEach(function (d) {
    rules.push({ action: 'deny', endpoint1: { tags: ['firealive-zone=' + d.fromLabel] }, endpoint2: { tags: ['firealive-zone=' + d.toLabel] }, direction: '>', reason: d.reason });
  });
  model.allowedFlows.forEach(function (f) {
    rules.push({ action: 'pass', endpoint1: { tags: ['firealive-zone=' + f.fromLabel] }, endpoint2: { tags: ['firealive-zone=' + f.toLabel] }, services: [{ protocol: f.protocol, dstPorts: [f.port] }], direction: '>', purpose: f.purpose });
  });
  rules.push({ action: 'deny', endpoint1: { any: true }, endpoint2: { any: true }, note: 'default-deny baseline' });
  return {
    apiVersion: 'core.contrail.juniper.net/v1alpha1', kind: 'FirewallPolicy',
    metadata: { name: 'firealive-segmentation' },
    note: 'Contrail FirewallPolicy intent. Bind firealive-zone tags to your VirtualNetworks/workloads and apply via your CN2 change-control; do not auto-push.',
    spec: { rules: rules }
  };
}

function renderCiscoAci(model) {
  return {
    model: 'application-centric (EPG + contract)',
    note: 'Structured segmentation intent in ACI vocabulary. Implement as EPGs and contracts in APIC via your change-control process; do not auto-push.',
    endpointGroups: model.zones.map(function (z) { return { epg: 'firealive-' + slug(z.label), zone: z.label, mappedSegment: z.segment }; }),
    vzAnyDefault: 'deny (no implicit permit; only the contracts below allow traffic)',
    contracts: model.allowedFlows.map(function (f) {
      return {
        name: 'firealive-' + slug(f.from) + '-to-' + slug(f.to),
        provider: 'firealive-' + slug(f.toLabel), consumer: 'firealive-' + slug(f.fromLabel),
        subject: { filter: f.protocol + '-' + f.port, protocol: f.protocol, dPort: f.port }, purpose: f.purpose
      };
    }),
    explicitlyNoContract: model.assertedDenies.map(function (d) {
      return { provider: 'firealive-' + slug(d.toLabel), consumer: 'firealive-' + slug(d.fromLabel), reason: d.reason };
    })
  };
}

function renderNsx(model) {
  var rules = [];
  model.assertedDenies.forEach(function (d) {
    rules.push({ action: 'DROP', name: 'firealive-deny-' + slug(d.fromLabel) + '-to-' + slug(d.toLabel), source: 'firealive-' + slug(d.fromLabel), destination: 'firealive-' + slug(d.toLabel), services: ['ANY'], reason: d.reason });
  });
  model.allowedFlows.forEach(function (f) {
    rules.push({ action: 'ALLOW', name: 'firealive-allow-' + slug(f.from) + '-to-' + slug(f.to), source: 'firealive-' + slug(f.fromLabel), destination: 'firealive-' + slug(f.toLabel), services: [f.protocol.toUpperCase() + '-' + f.port], purpose: f.purpose });
  });
  rules.push({ action: 'DROP', name: 'firealive-default-deny', source: 'ANY', destination: 'ANY', services: ['ANY'], note: 'default-deny baseline; lowest precedence' });
  return {
    model: 'DFW (groups + distributed firewall)',
    note: 'Structured DFW intent in NSX vocabulary. Implement as Groups and a SecurityPolicy with these rules; do not auto-push.',
    groups: model.zones.map(function (z) { return { group: 'firealive-' + slug(z.label), zone: z.label, mappedSegment: z.segment }; }),
    securityPolicy: { name: 'firealive-segmentation', category: 'Application', rules: rules }
  };
}

function renderOpenflow(model) {
  var flows = [];
  model.assertedDenies.forEach(function (d) {
    flows.push({ priority: 60000, match: { srcZone: d.fromLabel, dstZone: d.toLabel }, action: 'drop', reason: d.reason });
  });
  model.allowedFlows.forEach(function (f) {
    flows.push({ priority: 40000, match: { srcZone: f.fromLabel, dstZone: f.toLabel, ipProto: f.protocol, dstPort: f.port }, action: 'forward', purpose: f.purpose });
  });
  flows.push({ priority: 0, match: 'any', action: 'drop', note: 'table-miss default-deny' });
  return {
    model: 'flow-intent (controller-agnostic)',
    note: 'Logical flow intent. OpenFlow programming is controller-specific (ONOS/ODL/Ryu/Floodlight); translate srcZone/dstZone to the match fields your controller exposes. Do not auto-push.',
    zones: model.zones.map(function (z) { return { zone: z.label, mappedSegment: z.segment }; }),
    flows: flows
  };
}

function renderArista(model) {
  var rules = [];
  model.assertedDenies.forEach(function (d) {
    rules.push({ action: 'deny', source: 'tag:firealive-' + slug(d.fromLabel), destination: 'tag:firealive-' + slug(d.toLabel), reason: d.reason });
  });
  model.allowedFlows.forEach(function (f) {
    rules.push({ action: 'permit', source: 'tag:firealive-' + slug(f.fromLabel), destination: 'tag:firealive-' + slug(f.toLabel), protocol: f.protocol, port: f.port, purpose: f.purpose });
  });
  rules.push({ action: 'deny', source: 'any', destination: 'any', note: 'default-deny baseline' });
  return {
    model: 'tag-based segmentation (CloudVision)',
    note: 'Structured segmentation intent in CloudVision vocabulary using device tags. Implement via CVP Studios/configlets and your change-control process; do not auto-push.',
    tags: model.zones.map(function (z) { return { tag: 'firealive-' + slug(z.label), zone: z.label, mappedSegment: z.segment }; }),
    policy: { name: 'firealive-segmentation', rules: rules }
  };
}

function renderPolicy(platform, model) {
  var native;
  switch (platform) {
    case 'cilium': native = { ciliumPolicies: renderCilium(model) }; break;
    case 'calico': native = { calicoPolicies: renderCalico(model) }; break;
    case 'juniper-cn2': native = { contrailFirewallPolicy: renderCn2(model) }; break;
    case 'cisco-aci': native = { aci: renderCiscoAci(model) }; break;
    case 'vmware-nsx': native = { nsx: renderNsx(model) }; break;
    case 'openflow': native = { openflow: renderOpenflow(model) }; break;
    case 'arista-cv': native = { cloudvision: renderArista(model) }; break;
    case 'custom': native = {}; break;
    default: throw fail('UNSUPPORTED_PLATFORM', 'unsupported platform: ' + platform);
  }
  var out = advisoryHeader(platform, model);
  out.intent = canonicalIntent(model);
  Object.keys(native).forEach(function (k) { out[k] = native[k]; });
  return out;
}

function generateSegmentPolicy(networkMap, platform) {
  if (SUPPORTED_PLATFORMS.indexOf(platform) === -1) throw fail('UNSUPPORTED_PLATFORM', 'unsupported platform: ' + platform);
  var model = buildSegmentationModel(networkMap);
  var rendered = renderPolicy(platform, model);
  return {
    platform: platform,
    format: 'json',
    filename: 'firealive-segmentation-' + platform + '.json',
    generatedAt: model.generatedAt,
    advisory: ADVISORY_TEXT,
    policy: rendered,
    content: JSON.stringify(rendered, null, 2)
  };
}

module.exports = {
  SUPPORTED_PLATFORMS: SUPPORTED_PLATFORMS,
  REQUIRED_FLOWS: REQUIRED_FLOWS,
  ROLE_ALIASES: ROLE_ALIASES,
  MANAGEMENT_ROLES: MANAGEMENT_ROLES,
  PRIVATE_ROLES: PRIVATE_ROLES,
  canonicalRole: canonicalRole,
  sensitivityOf: sensitivityOf,
  buildSegmentationModel: buildSegmentationModel,
  renderPolicy: renderPolicy,
  generateSegmentPolicy: generateSegmentPolicy
};
