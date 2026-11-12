// 画面の切り替え（docs/SCREENS.md の画面遷移図）
//   S01 受付票 →（はじめて／指紋が違う）S02 → S03 診察中 →（失敗）S06 エラー → S01
import {useEffect, useState} from 'react';
import './App.css';
import {CancelCheck, CheckConnection} from '../wailsjs/go/main/App';
import {main} from '../wailsjs/go/models';
import {EventsOff, EventsOn} from '../wailsjs/runtime/runtime';
import {effectiveSudo, emptyForm, Form, Reception} from './screens/Reception';
import {HostKeyDialog} from './screens/HostKeyDialog';
import {Checkup, initialSteps, Step} from './screens/Checkup';
import {ErrorDialog} from './screens/ErrorDialog';

type Screen = 'reception' | 'checkup';

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
    const [finished, setFinished] = useState(false);

    // Go 側から届く進み具合（S03）
    useEffect(() => {
        EventsOn('checkup:progress', (p: Progress) => {
            setSteps(prev => prev.map(s => s.id === p.step ? {...s, status: p.status, detail: p.detail} : s));
        });
        return () => EventsOff('checkup:progress');
    }, []);

    function backToReception() {
        setScreen('reception');
        setDialog({kind: 'none'});
    }

    async function start(trustFingerprint = '') {
        setDialog({kind: 'none'});
        setSteps(initialSteps());
        setFinished(false);
        setScreen('checkup');

        let res: main.ConnectionResult;
        try {
            res = await CheckConnection(main.ReceptionForm.createFrom({
                host: form.host.trim(),
                port: Number(form.port),
                user: form.user.trim(),
                authType: form.authType,
                password: form.authType === 'password' ? form.password : '',
                keyPath: form.authType === 'key' ? form.keyPath : '',
                keyPassphrase: form.authType === 'key' ? form.keyPassphrase : '',
                sudoPassword: effectiveSudo(form),
                webRoot: form.webRoot.trim(),
                trustFingerprint,
            }));
        } catch (e) {
            setDialog({kind: 'error', message: String(e)});
            return;
        }

        switch (res.status) {
            case 'ok':
                setFinished(true);
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
            {screen === 'reception' && <Reception form={form} onChange={setForm} onSubmit={() => start()}/>}
            {screen === 'checkup' && (
                <Checkup host={form.name.trim() ? `${form.name.trim()}（${form.host.trim()}）` : form.host.trim()} steps={steps} finished={finished}
                         onCancel={() => CancelCheck()} onBack={backToReception}/>
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
