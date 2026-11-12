// 画面の切り替え（docs/SCREENS.md の画面遷移図）
//   S01 受付票 →（はじめて／指紋が違う）S02 → S03 診察中 → S04 カルテ ⇄ S05 所見の詳細
//                                             └（失敗）S06 エラー → S01
import {useEffect, useState} from 'react';
import './App.css';
import {CancelCheck, Diagnose, ListServers} from '../wailsjs/go/main/App';
import {main, store} from '../wailsjs/go/models';
import {EventsOff, EventsOn} from '../wailsjs/runtime/runtime';
import {effectiveSudo, emptyForm, Form, Reception} from './screens/Reception';
import {HostKeyDialog} from './screens/HostKeyDialog';
import {Checkup, initialSteps, Step} from './screens/Checkup';
import {ErrorDialog} from './screens/ErrorDialog';
import {Karte} from './screens/Karte';

type Screen = 'reception' | 'checkup' | 'karte';

type Dialog =
    | { kind: 'none' }
    | { kind: 'hostkey-unknown'; fingerprint: string }
    | { kind: 'hostkey-mismatch'; fingerprint: string; expected: string }
    | { kind: 'error'; message: string };

type Progress = { step: string; status: 'running' | 'done'; detail?: string };

function App() {
    const [form, setForm] = useState<Form>(emptyForm);
    const [screen, setScreen] = useState<Screen>('reception');
    const [dialog, setDialog] = useState<Dialog>({kind: 'none'});
    const [steps, setSteps] = useState<Step[]>(initialSteps());
    const [result, setResult] = useState<main.ConnectionResult | null>(null);
    const [servers, setServers] = useState<store.Server[]>([]);
    const [storeError, setStoreError] = useState('');

    async function loadServers() {
        try {
            const list = await ListServers();
            setServers(list.servers ?? []);
            setStoreError(list.error ?? '');
        } catch (e) {
            setStoreError(String(e));
        }
    }

    useEffect(() => {
        loadServers();
    }, []);

    // Go 側から届く進み具合（S03）
    useEffect(() => {
        EventsOn('checkup:progress', (p: Progress) => {
            setSteps(prev => prev.map(s => s.id === p.step ? {...s, status: p.status, detail: p.detail} : s));
        });
        return () => EventsOff('checkup:progress');
    }, []);

    const title = form.name.trim() ? `${form.name.trim()}（${form.host.trim()}）` : form.host.trim();

    function backToReception() {
        setScreen('reception');
        setDialog({kind: 'none'});
    }

    // 「新しく受付」：認証情報をメモリから消す（SCREENS.md の決定 3）
    function newReception() {
        setForm(emptyForm);
        setResult(null);
        backToReception();
    }

    async function start(trustFingerprint = '') {
        setDialog({kind: 'none'});
        setSteps(initialSteps());
        setResult(null);
        setScreen('checkup');

        let res: main.ConnectionResult;
        try {
            res = await Diagnose(main.ReceptionForm.createFrom({
                host: form.host.trim(),
                port: Number(form.port),
                user: form.user.trim(),
                authType: form.authType,
                password: form.authType === 'password' ? form.password : '',
                keyPath: form.authType === 'key' ? form.keyPath : '',
                keyPassphrase: form.authType === 'key' ? form.keyPassphrase : '',
                sudoPassword: effectiveSudo(form),
                webRoot: form.webRoot.trim(),
                label: form.name.trim(),
                trustFingerprint,
            }));
        } catch (e) {
            setDialog({kind: 'error', message: String(e)});
            return;
        }

        switch (res.status) {
            case 'ok':
                setResult(res);
                setScreen('karte');
                loadServers();
                break;
            case 'hostkey_unknown':
                setScreen('reception');
                setDialog({kind: 'hostkey-unknown', fingerprint: res.fingerprint ?? ''});
                break;
            case 'hostkey_mismatch':
                setScreen('reception');
                setDialog({kind: 'hostkey-mismatch', fingerprint: res.fingerprint ?? '', expected: res.expected ?? ''});
                break;
            case 'canceled':
                backToReception();
                break;
            default: // error / unsupported_os
                setDialog({kind: 'error', message: res.message});
        }
    }

    return (
        <div className="page">
            {screen === 'reception' && <Reception form={form} onChange={setForm} onSubmit={() => start()}
                                                       servers={servers} storeError={storeError}/>}
            {screen === 'checkup' && (
                <Checkup host={title} steps={steps} onCancel={() => CancelCheck()}/>
            )}
            {screen === 'karte' && result && (
                <Karte title={title} result={result}
                       maskTargets={{host: form.host, user: form.user, name: form.name}}
                       onRetry={() => start()} onNew={newReception}/>
            )}

            {dialog.kind === 'hostkey-unknown' && (
                <HostKeyDialog kind="unknown" fingerprint={dialog.fingerprint}
                               onCancel={backToReception} onConnect={() => start(dialog.fingerprint)}/>
            )}
            {dialog.kind === 'hostkey-mismatch' && (
                <HostKeyDialog kind="mismatch" fingerprint={dialog.fingerprint} expected={dialog.expected}
                               onClose={backToReception}/>
            )}
            {dialog.kind === 'error' && <ErrorDialog message={dialog.message} onClose={backToReception}/>}
        </div>
    );
}

export default App;
