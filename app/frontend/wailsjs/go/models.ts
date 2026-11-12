export namespace karte {
	
	export class Finding {
	    code: string;
	    grade: string;
	    params: Record<string, string>;
	    evidence: string;
	    title: string;
	    what: string;
	    why: string;
	    howToFix: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.grade = source["grade"];
	        this.params = source["params"];
	        this.evidence = source["evidence"];
	        this.title = source["title"];
	        this.what = source["what"];
	        this.why = source["why"];
	        this.howToFix = source["howToFix"];
	    }
	}
	export class CheckResult {
	    checkId: string;
	    name: string;
	    grade: string;
	    summary: string;
	    findings: Finding[];
	    evidence: string;
	
	    static createFrom(source: any = {}) {
	        return new CheckResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.checkId = source["checkId"];
	        this.name = source["name"];
	        this.grade = source["grade"];
	        this.summary = source["summary"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.evidence = source["evidence"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class ConnectionResult {
	    status: string;
	    message: string;
	    keyType?: string;
	    fingerprint?: string;
	    expected?: string;
	    os: osinfo.Info;
	    overallGrade?: string;
	    gradeLabel?: string;
	    checks?: karte.CheckResult[];
	    finishedAt?: string;
	    saveWarning?: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.message = source["message"];
	        this.keyType = source["keyType"];
	        this.fingerprint = source["fingerprint"];
	        this.expected = source["expected"];
	        this.os = this.convertValues(source["os"], osinfo.Info);
	        this.overallGrade = source["overallGrade"];
	        this.gradeLabel = source["gradeLabel"];
	        this.checks = this.convertValues(source["checks"], karte.CheckResult);
	        this.finishedAt = source["finishedAt"];
	        this.saveWarning = source["saveWarning"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ReceptionForm {
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    password: string;
	    keyPath: string;
	    keyPassphrase: string;
	    sudoPassword: string;
	    webRoot: string;
	    label: string;
	    trustFingerprint: string;
	
	    static createFrom(source: any = {}) {
	        return new ReceptionForm(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.password = source["password"];
	        this.keyPath = source["keyPath"];
	        this.keyPassphrase = source["keyPassphrase"];
	        this.sudoPassword = source["sudoPassword"];
	        this.webRoot = source["webRoot"];
	        this.label = source["label"];
	        this.trustFingerprint = source["trustFingerprint"];
	    }
	}
	export class ServerList {
	    servers: store.Server[];
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerList(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.servers = this.convertValues(source["servers"], store.Server);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace osinfo {
	
	export class Info {
	    id: string;
	    name: string;
	    versionId: string;
	    prettyName: string;
	
	    static createFrom(source: any = {}) {
	        return new Info(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.versionId = source["versionId"];
	        this.prettyName = source["prettyName"];
	    }
	}

}

export namespace store {
	
	export class Server {
	    id: number;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    keyPath: string;
	    webRoot: string;
	    label: string;
	    lastDiagnosedAt: string;
	    lastGrade: string;
	
	    static createFrom(source: any = {}) {
	        return new Server(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.keyPath = source["keyPath"];
	        this.webRoot = source["webRoot"];
	        this.label = source["label"];
	        this.lastDiagnosedAt = source["lastDiagnosedAt"];
	        this.lastGrade = source["lastGrade"];
	    }
	}

}

