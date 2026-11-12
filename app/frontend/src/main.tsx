import React from 'react'
import {createRoot} from 'react-dom/client'
// フォントはアプリに同梱する（外部から読み込まない＝ローカル完結の方針）
import '@fontsource/shippori-mincho/japanese-800.css'
import '@fontsource/shippori-mincho/latin-800.css'
import '@fontsource/biz-udpgothic/japanese-400.css'
import '@fontsource/biz-udpgothic/latin-400.css'
import '@fontsource/biz-udpgothic/japanese-700.css'
import '@fontsource/biz-udpgothic/latin-700.css'
import '@fontsource/biz-udgothic/japanese-400.css'
import '@fontsource/biz-udgothic/latin-400.css'
import './style.css'
import App from './App'

const container = document.getElementById('root')

const root = createRoot(container!)

root.render(
    <React.StrictMode>
        <App/>
    </React.StrictMode>
)
