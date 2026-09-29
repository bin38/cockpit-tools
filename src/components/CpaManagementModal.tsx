import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { X, CloudUpload, RefreshCw, Server, Trash2, Link2 } from 'lucide-react';
import { isStandardCodexOAuthAccount, type CodexAccount } from '../types/codex';
import { useModalScrollLock } from '../hooks/useModalScrollLock';
import { useEscCloseTopmost } from '../hooks/useEscClose';
import { ModalErrorMessage, useModalErrorState } from './ModalErrorMessage';
import * as api from '../services/cpaManagementService';
import './CpaManagementModal.css';

type Confirmation =
  | { kind: 'upload'; ids: string[] }
  | { kind: 'delete'; file: api.CpaRemoteFile; accountId?: string }
  | { kind: 'disconnect' }
  | { kind: 'link'; file: api.CpaRemoteFile };
interface Props {
  accounts: CodexAccount[];
  initialSelected?: Set<string>;
  maskAccountText: (value: string) => string;
  onClose: () => void;
  onAccountsChanged: () => Promise<void>;
}

export function CpaManagementModal({ accounts, initialSelected, maskAccountText: mask, onClose, onAccountsChanged }: Props) {
  const { t } = useTranslation();
  const [connection, setConnection] = useState<api.CpaConnection | null>(null);
  const [initialized, setInitialized] = useState(false);
  const [editing, setEditing] = useState(false);
  const [baseUrl, setBaseUrl] = useState('');
  const [key, setKey] = useState('');
  const [version, setVersion] = useState('auto');
  const [autoSync, setAutoSync] = useState(true);
  const [defaultUpload, setDefaultUpload] = useState(false);
  const [allowInsecureHttp, setAllowInsecureHttp] = useState(false);
  const [files, setFiles] = useState<api.CpaRemoteFile[]>([]);
  const [remoteLoaded, setRemoteLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set(initialSelected));
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [deleteLocal, setDeleteLocal] = useState(false);
  const [linkAccountId, setLinkAccountId] = useState('');
  const [results, setResults] = useState<api.CpaUploadResult[]>([]);
  const [notice, setNotice] = useState('');
  const error = useModalErrorState();
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const eligible = accounts.filter(isStandardCodexOAuthAccount);
  const ids = eligible.filter(a => selected.has(a.id)).map(a => a.id);
  const label = (id: string) => mask(accounts.find(a => a.id === id)?.email || id);
  const explain = useCallback((cause: unknown) => t(`cpa.errors.${api.cpaErrorKey(cause)}`, t('cpa.errors.CPA_UNKNOWN')), [t]);
  useModalScrollLock(true);
  useEscCloseTopmost(true, () => {
    if (confirmation && !busyRef.current) setConfirmation(null);
    else onClose();
  });
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const load = useCallback(async () => {
    const result = await api.getConnection();
    if (!mounted.current) return;
    setConnection(result); setInitialized(true);
    if (!result) setEditing(true);
  }, []);
  const refreshRemote = async (id: string) => {
    setRemoteLoaded(false); setFiles([]);
    const result = await api.listCredentials(id);
    if (mounted.current) { setFiles(result); setRemoteLoaded(true); }
  };
  const execute = useCallback(async (action: () => Promise<void>) => {
    if (busyRef.current) return;
    busyRef.current = true; setBusy(true); error.clear(); setNotice('');
    try { await action(); }
    catch (cause) { if (mounted.current) error.report(explain(cause)); }
    finally { busyRef.current = false; if (mounted.current) setBusy(false); }
  }, [error.clear, error.report, explain]);
  useEffect(() => { void execute(load); }, [execute, load]);
  const beginEdit = () => {
    if (busyRef.current) return;
    setBaseUrl(connection?.baseUrl || ''); setVersion(connection?.apiVersion || 'auto');
    setAutoSync(connection?.autoSync ?? true); setDefaultUpload(connection?.defaultUpload ?? false);
    setAllowInsecureHttp(connection?.allowInsecureHttp ?? false);
    setKey(''); setEditing(true); error.clear();
  };
  const save = () => void execute(async () => {
    const result = await api.saveConnection({ id: connection?.id || null, baseUrl,
      key: key.trim() || null, version, autoSync, defaultUpload, allowInsecureHttp });
    if (!mounted.current) return;
    setKey(''); setConnection(result); setEditing(false); setResults([]);
    setNotice(t('cpa.saved'));
    await refreshRemote(result.id);
  });
  const ask = (next: Confirmation) => {
    if (busyRef.current) return;
    setConfirmation(next); setDeleteLocal(false); setLinkAccountId(''); error.clear(); setNotice('');
  };
  const confirm = () => {
    if (!confirmation || !connection) return;
    const snapshot = confirmation;
    const id = connection.id;
    void execute(async () => {
      if (snapshot.kind === 'disconnect') {
        await api.disconnect(id);
        if (!mounted.current) return;
        setConfirmation(null); setFiles([]); setRemoteLoaded(false); setResults([]);
        setConnection(null); setKey(''); setBaseUrl(''); setEditing(true); setDefaultUpload(false);
        setAllowInsecureHttp(false);
        return;
      }
      if (snapshot.kind === 'upload') {
        const outcome = await api.uploadAccounts(id, snapshot.ids);
        if (mounted.current) setResults(outcome);
      } else if (snapshot.kind === 'delete') {
        await api.deleteCredential(id, snapshot.file.name, deleteLocal);
        if (mounted.current) {
          setFiles(previous => previous.filter(f => f.name !== snapshot.file.name));
          setConfirmation(null); setNotice(t('cpa.deleted'));
        }
        if (deleteLocal) await onAccountsChanged();
      } else {
        if (!linkAccountId) return;
        await api.linkCredential(id, snapshot.file.name, linkAccountId);
        if (mounted.current) setNotice(t('cpa.linkedNotice'));
      }
      if (!mounted.current) return;
      setConfirmation(null);
      await load();
      if (mounted.current) await refreshRemote(id);
    });
  };
  const name = (file: api.CpaRemoteFile) => mask(file.email || file.name);
  const canAct = initialized && !busy && !editing && !!connection && !connection.blocked;
  return createPortal(
    <div className="modal-overlay cpa-overlay">
      <div className="modal cpa-modal" role="dialog" aria-modal="true" aria-labelledby="cpa-title" aria-busy={busy}>
        <div className="modal-header">
          <h2 id="cpa-title"><Server size={19} /> {t('cpa.title')}</h2>
          <button className="btn btn-secondary icon-only" onClick={onClose} aria-label={t('common.close')}><X size={18} /></button>
        </div>
        <div className="modal-body">
          <p className="cpa-hint">{t('cpa.description')}</p>
          <ModalErrorMessage message={error.message} scrollKey={error.scrollKey} />
          {notice && <p role="status" className="cpa-notice">{notice}</p>}
          {!initialized && !busy && <button className="btn btn-secondary" onClick={() => void execute(load)}>{t('cpa.retry')}</button>}
          {connection?.lastError && <p className="cpa-warning">{explain(connection.lastError)}</p>}
          {connection?.allowInsecureHttp && connection.baseUrl.startsWith('http:') && !editing && <p className="cpa-warning" role="note">{t('cpa.httpWarning')}</p>}
          {confirmation ? (
            <section className="cpa-confirm">
              <h3>{t(`cpa.confirm.${confirmation.kind}`)}</h3>
              <p className="cpa-address">{connection?.baseUrl}</p>
              {confirmation.kind === 'upload' && <>
                <p>{t('cpa.uploadNotice', { count: confirmation.ids.length })}</p>
                <ul>{confirmation.ids.map(id => <li key={id}>{label(id)}</li>)}</ul>
              </>}
              {confirmation.kind === 'disconnect' && <p>{t('cpa.disconnectNotice')}</p>}
              {confirmation.kind === 'delete' && <>
                <p>{name(confirmation.file)}</p><code>{mask(confirmation.file.name)}</code>
                <p>{t('cpa.deleteNotice')}</p>
                {confirmation.accountId && <label className="cpa-checkbox">
                  <input type="checkbox" checked={deleteLocal} disabled={busy} onChange={e => setDeleteLocal(e.target.checked)} />
                  {t('cpa.deleteLocal', { name: label(confirmation.accountId) })}
                </label>}
              </>}
              {confirmation.kind === 'link' && <>
                <p>{name(confirmation.file)} · {mask(confirmation.file.name)}</p>
                <p>{t('cpa.linkNotice')}</p>
                <select aria-label={t('cpa.chooseAccount')} value={linkAccountId} disabled={busy} onChange={e => setLinkAccountId(e.target.value)}>
                  <option value="">{t('cpa.chooseAccount')}</option>
                  {eligible.filter(a => !connection?.bindings.some(b => b.accountId === a.id)).map(a => <option key={a.id} value={a.id}>{label(a.id)}</option>)}
                </select>
              </>}
            </section>
          ) : <>
            {initialized && editing ? <fieldset className="cpa-settings" disabled={busy}>
              <legend>{t('cpa.settings')}</legend>
              <label>{t('cpa.server')}<input value={baseUrl} onChange={e => { setBaseUrl(e.target.value); setAllowInsecureHttp(false); }} placeholder="https://cpa.example.com" autoComplete="off" /></label>
              <label>{t('cpa.key')}<input type="password" value={key} onChange={e => setKey(e.target.value)} autoComplete="new-password" placeholder={connection ? t('cpa.keepKey') : 'Management Key'} /></label>
              <label>{t('cpa.version')}<select value={version} onChange={e => setVersion(e.target.value)}>
                <option value="auto">{t('cpa.autoVersion')}</option><option value="v8">v8</option><option value="v0">v0</option>
              </select></label>
              <label className="cpa-checkbox"><input type="checkbox" checked={autoSync} onChange={e => setAutoSync(e.target.checked)} />{t('cpa.autoSync')}</label>
              <label className="cpa-checkbox"><input type="checkbox" checked={defaultUpload} onChange={e => setDefaultUpload(e.target.checked)} />{t('cpa.defaultUpload')}</label>
              <label className="cpa-checkbox"><input type="checkbox" checked={allowInsecureHttp} onChange={e => setAllowInsecureHttp(e.target.checked)} aria-describedby="cpa-http-warning" />{t('cpa.allowInsecureHttp')}</label>
              <p id="cpa-http-warning" className="cpa-warning">{t('cpa.httpWarning')}</p>
              <p className="cpa-hint">{t('cpa.settingsHint')}</p>
              <div className="cpa-actions"><button className="btn btn-primary" disabled={!baseUrl.trim() || (!connection && !key.trim())} onClick={save}>{t('cpa.testSave')}</button>
                {connection && <button className="btn btn-secondary" onClick={() => { setKey(''); setEditing(false); }}>{t('common.cancel')}</button>}</div>
            </fieldset> : connection && <div className="cpa-connection">
              <div><strong>{connection.baseUrl}</strong><span>{connection.apiVersion} · {t(connection.autoSync ? 'cpa.syncOn' : 'cpa.syncOff')} · {t(connection.defaultUpload ? 'cpa.defaultOn' : 'cpa.defaultOff')}</span></div>
              <button className="btn btn-secondary" disabled={busy} onClick={beginEdit}>{t('cpa.settings')}</button>
              <button className="btn btn-secondary" disabled={busy} onClick={() => ask({ kind: 'disconnect' })}>{t('cpa.disconnect')}</button>
            </div>}
            {connection && !editing && <>
              <section>
                <div className="cpa-section-heading"><h3>{t('cpa.localAccounts')}</h3>
                  <button className="btn btn-primary" disabled={!canAct || ids.length === 0 || ids.length > 100} onClick={() => ask({ kind: 'upload', ids })}><CloudUpload size={15} />{t('cpa.upload', { count: ids.length })}</button></div>
                <p className="cpa-hint">{t('cpa.localHint')}</p>
                <div className="cpa-account-list">
                  {eligible.length === 0 && <p>{t('cpa.noLocal')}</p>}
                  {eligible.map(a => {
                    const binding = connection.bindings.find(b => b.accountId === a.id);
                    return <div className="cpa-row" key={a.id}>
                      <label className="cpa-checkbox"><input type="checkbox" disabled={busy} checked={selected.has(a.id)} onChange={e => setSelected(previous => {
                        const next = new Set(previous); if (e.target.checked) next.add(a.id); else next.delete(a.id); return next;
                      })} />{label(a.id)}</label>
                      <span className="cpa-row-detail">{binding ? (binding.error ? explain(binding.error) : t('cpa.synced', { time: binding.lastSyncedAt ? new Date(binding.lastSyncedAt * 1000).toLocaleString() : '—' })) : t('cpa.notLinked')}</span>
                      {binding?.active && <button className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void execute(async () => { await api.stopSync(connection.id, a.id); if (mounted.current) await load(); })}>{t('cpa.stopSync')}</button>}
                    </div>;
                  })}
                </div>
                {results.length > 0 && <ul className="cpa-results" role="status">{results.map(r => <li key={r.accountId}>{label(r.accountId)}：{r.error ? explain(r.error) : t('cpa.uploaded')}</li>)}</ul>}
              </section>
              <section>
                <div className="cpa-section-heading"><h3>{t('cpa.remoteAccounts')}</h3>
                  <button className="btn btn-secondary" disabled={!canAct} onClick={() => void execute(async () => { await load(); if (mounted.current) await refreshRemote(connection.id); })}><RefreshCw size={15} />{t('cpa.loadRemote')}</button></div>
                {!remoteLoaded ? <p className="cpa-hint">{t('cpa.remoteNotLoaded')}</p> : files.length === 0 ? <p>{t('cpa.noRemote')}</p> : <div className="cpa-remote-list">{files.map(file => {
                  const binding = connection.bindings.find(b => b.fileName === file.name);
                  const writable = api.canManageCpaFile(file);
                  return <div className="cpa-remote-row" key={file.name}>
                    <div className="cpa-remote-identity"><strong>{name(file)}</strong><code>{mask(file.name)}</code><span>{t(file.disabled ? 'cpa.disabled' : file.unavailable ? 'cpa.unavailable' : 'cpa.enabled')}{binding && ` · ${t('cpa.linked')} ${label(binding.accountId)}`}{!writable && ` · ${t('cpa.readOnly')}`}</span></div>
                    <div className="cpa-actions">
                      {!binding && <button className="btn btn-secondary btn-sm" disabled={!canAct || !writable} onClick={() => ask({ kind: 'link', file })}><Link2 size={14} />{t('cpa.link')}</button>}
                      <button className="btn btn-secondary btn-sm" disabled={!canAct || !writable} onClick={() => void execute(async () => { await api.setDisabled(connection.id, file.name, !file.disabled); if (mounted.current) await refreshRemote(connection.id); })}>{t(file.disabled ? 'cpa.enable' : 'cpa.disable')}</button>
                      <button className="btn btn-secondary btn-sm" disabled={!canAct || !writable} onClick={() => ask({ kind: 'delete', file, accountId: binding?.accountId })}><Trash2 size={14} />{t('common.delete')}</button>
                    </div>
                  </div>;
                })}</div>}
              </section>
            </>}
          </>}
        </div>
        <div className="modal-footer">
          {busy && <span role="status">{t('common.loading')}</span>}
          {confirmation ? <><button className="btn btn-secondary" disabled={busy} onClick={() => { setConfirmation(null); error.clear(); }}>{t('common.cancel')}</button>
            <button className="btn btn-primary" disabled={busy || (confirmation.kind === 'link' && !linkAccountId)} onClick={confirm}>{t('common.confirm')}</button></>
            : <button className="btn btn-secondary" onClick={onClose}>{t('common.close')}</button>}
        </div>
      </div>
    </div>, document.body,
  );
}
