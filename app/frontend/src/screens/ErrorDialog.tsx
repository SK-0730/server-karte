// S06 エラー（docs/SCREENS.md）
type Props = {
    message: string;
    onClose: () => void;
};

export function ErrorDialog({message, onClose}: Props) {
    return (
        <div className="overlay">
            <div className="dialog" role="alertdialog">
                <h2>診断できませんでした</h2>
                <p>{message}</p>
                <div className="dialog-buttons">
                    <button type="button" className="primary" onClick={onClose}>受付票に戻る</button>
                </div>
            </div>
        </div>
    );
}
