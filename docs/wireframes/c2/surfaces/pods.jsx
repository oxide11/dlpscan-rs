/* ===== surfaces/pods.jsx ===== */
// Pod Inventory surface. Live-backed by siphon-api's
// /v1/k8s/pods (gated by the chart's api.k8sRoll.enabled=true
// Role). The endpoint distinguishes three product states:
//   1. 200 { in_cluster: true, pods: [...] }  — normal, render rows
//   2. 200 { in_cluster: false, pods: [] }    — siphon-api is
//      running outside a cluster (typical local `cargo run`);
//      render a calm informational panel, NOT a red error
//   3. non-2xx                                — a real failure
//      (RBAC denied, apiserver unreachable, feature flag off);
//      render the error surface
function Pods() {
  // 5 s cadence matches kubelet's status push interval so anything
  // faster just repeats the same snapshot. Joins the shared 5s
  // bucket so co-resident dashboards co-tick on the same edge.
  const tick = window.useSharedPoll(5000);
  const px = window.useSiphonApi('/v1/k8s/pods', [tick]);

  const data       = px.data;
  const inCluster  = !!(data && data.in_cluster);
  const pods       = (data && data.pods) || [];
  const namespace  = (data && data.namespace) || null;

  // Per-deployment roll-up. The API already tags each pod with
  // its `app.kubernetes.io/component` label; fall back to a
  // synthetic bucket so un-labelled pods still show up.
  const byDeployment = React.useMemo(() => {
    const m = new Map();
    for (const p of pods) {
      const key = p.deployment || '(unlabeled)';
      const arr = m.get(key) || [];
      arr.push(p);
      m.set(key, arr);
    }
    return [...m.entries()].sort((a,b) => a[0].localeCompare(b[0]));
  }, [pods]);

  const total     = pods.length;
  const ready     = pods.filter(p => p.ready).length;
  const unhealthy = total - ready;
  const restarts  = pods.reduce((a, p) => a + (p.restarts || 0), 0);

  // LivePill: 'live' whenever the endpoint answered 200 — even
  // when `in_cluster === false` the endpoint is live, there
  // just aren't any pods to show. The info banner below carries
  // the "why" so this chip stays simple and non-alarming.
  const pillSource = px.loading ? 'loading'
                   : px.error   ? 'offline'
                   : 'live';

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="crumbs">Operate · Pod Inventory{namespace ? ' · ' + namespace : ''}</div>
          <h1>Pods</h1>
        </div>
        <div className="actions">
          <window.LivePill
            source={pillSource}
            onClick={() => px.refetch()}
            title={px.error || (inCluster ? 'siphon-api is in-cluster' : 'siphon-api is not running in a cluster')}
          />
          <button className="btn ghost" onClick={() => px.refetch()}>Refresh</button>
        </div>
      </div>

      <div className="grid grid-4" style={{marginBottom:'var(--gap)'}}>
        <div className="box"><div className="stat">
          <span className="s-label">Pods total</span>
          <span className="s-val">{px.loading && !data ? '…' : total}</span>
          <span className="s-delta">{namespace || 'resolving namespace'}</span>
        </div></div>
        <div className="box"><div className="stat">
          <span className="s-label">Ready</span>
          <span className="s-val" style={{color: ready === total && total > 0 ? 'var(--safe)' : undefined}}>
            {px.loading && !data ? '…' : ready}
          </span>
          <span className="s-delta">
            {total === 0 ? '—' : Math.round((ready / total) * 100) + '% of fleet'}
          </span>
        </div></div>
        <div className="box"><div className="stat">
          <span className="s-label">Unhealthy</span>
          <span className="s-val" style={{color: unhealthy > 0 ? 'var(--amber)' : undefined}}>
            {px.loading && !data ? '…' : unhealthy}
          </span>
          <span className="s-delta">Failed, pending, or not-ready</span>
        </div></div>
        <div className="box"><div className="stat">
          <span className="s-label">Restarts</span>
          <span className="s-val" style={{color: restarts > 0 ? 'var(--amber)' : undefined}}>
            {px.loading && !data ? '…' : restarts}
          </span>
          <span className="s-delta">Sum across pod containers</span>
        </div></div>
      </div>

      {px.error ? (
        <div className="box" style={{borderColor:'var(--red)', marginBottom:'var(--gap)'}}>
          <div className="box-title">
            <span className="t" style={{color:'var(--red)'}}>Pod discovery unavailable</span>
            <span className="k">/v1/k8s/pods</span>
          </div>
          <div className="mono" style={{fontSize:11, color:'var(--ink-soft)', lineHeight:1.6}}>
            <div>{px.error}</div>
            <div style={{marginTop:6}}>
              The Ops view needs siphon-api built with
              <code> --features k8s-roll</code> and the Role provisioned
              by the Helm chart (<code>api.k8sRoll.enabled=true</code>).
            </div>
          </div>
        </div>
      ) : null}

      {!px.error && data && !inCluster ? (
        <div className="box" style={{marginBottom:'var(--gap)'}}>
          <div className="box-title">
            <span className="t">Not running in a cluster</span>
            <span className="k">standalone siphon-api</span>
          </div>
          <div className="mono" style={{fontSize:11, color:'var(--ink-soft)', lineHeight:1.6}}>
            siphon-api couldn't find a kubeconfig or an in-cluster
            service-account token, so there are no pods to list. This is
            the expected state for a local
            <code> cargo run</code> or a containerised siphon-api that
            isn't deployed via the Helm chart. Deploy with
            <code> api.k8sRoll.enabled=true</code> to populate this view.
          </div>
        </div>
      ) : null}

      {!px.error && data && inCluster && pods.length === 0 ? (
        <div className="box" style={{marginBottom:'var(--gap)'}}>
          <div className="box-title">
            <span className="t">No Siphon pods visible</span>
            <span className="k">{namespace || 'default'}</span>
          </div>
          <div className="mono" style={{fontSize:11, color:'var(--ink-soft)', lineHeight:1.6}}>
            No pods in this namespace carry the
            <code> app.kubernetes.io/part-of=siphon</code> label yet.
            If you just installed the Helm chart this should populate
            within a few seconds.
          </div>
        </div>
      ) : null}

      {pods.length > 0 ? (
        <div className="box">
          <div className="box-title">
            <span className="t">Deployments</span>
            <span className="k">phase · ready · restarts · node</span>
          </div>
          <div className="pod-row label" style={{borderBottom:'1.5px solid var(--line)'}}>
            <span>●</span><span>Deployment</span><span>Ready</span><span>Restarts</span><span>Image</span><span>Phase</span><span></span>
          </div>
          {byDeployment.map(([dep, group]) => {
            const readyN = group.filter(p => p.ready).length;
            const anyBad = group.some(p => p.phase === 'Failed' || p.phase === 'Unknown');
            const tone   = readyN === group.length ? 'ok' : anyBad ? 'bad' : 'warn';
            const restartsN = group.reduce((a, p) => a + (p.restarts || 0), 0);
            const firstImage = (group[0] && group[0].image) || '—';
            const phaseLabel = group.every(p => p.phase === 'Running') ? 'Running'
                             : group.find(p => p.phase === 'Failed') ? 'Failed'
                             : group[0] ? group[0].phase : '—';
            return (
              <div className="pod-row" key={dep}>
                <span className={`dot-k ${tone}`} />
                <span className="name">{dep} <span className="v">{group.length} {group.length === 1 ? 'pod' : 'pods'}</span></span>
                <span className="mono">{readyN}/{group.length}</span>
                <span className="mono">{restartsN}</span>
                <span className="mono" title={firstImage} style={{overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{firstImage}</span>
                <span className={`chip chip--${tone === 'ok' ? 'safe' : tone === 'warn' ? 'warn' : 'red'}`}>{phaseLabel}</span>
                <span className="arrow">→</span>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
Object.assign(window, { Pods });

