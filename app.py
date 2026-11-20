"""Tableau de bord : streamlit run app.py"""
import json
import streamlit as st
from soc_agent import config
from soc_agent.agent import analyze
from soc_agent.actions import execute

st.set_page_config(page_title="Agent SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ Agent SOC - triage d'alertes explicable")

alerts = json.loads(config.DATASET.read_text(encoding="utf-8"))
with st.sidebar:
    backend = st.radio("Backend LLM", ["mock", "ollama"], help="ollama = vrai LLM local ; mock = simulation hors-ligne")
    protected = st.toggle("Garde-fous activés (anti-injection)", value=True)
    st.caption("Désactive les garde-fous puis analyse une alerte piégée pour montrer l'attaque.")

labels = {a["id"]: f"{a['id']} - {a['scenario']}{' ⚠ injection' if a['ground_truth']['injection'] else ''}" for a in alerts}
aid = st.selectbox("Alerte", list(labels), format_func=labels.get)
alert = next(a for a in alerts if a["id"] == aid)
c1, c2 = st.columns(2)
with c1:
    st.subheader("Alerte brute (SIEM)")
    st.json({k: v for k, v in alert.items() if k != "ground_truth"})
if st.button("Analyser", type="primary"):
    st.session_state["d"] = analyze(alert, backend, protected)
d = st.session_state.get("d")
if d and d["alert_id"] == aid:
    with c2:
        st.subheader("Décision de l'agent")
        icon = {"incident": "🔴", "suspicious": "🟠", "false_positive": "🟢"}[d["verdict"]]
        st.metric("Verdict", f"{icon} {d['verdict']}", f"confiance {d['confidence']:.0%}")
        st.write(f"**MITRE ATT&CK** : {d['technique']['id']} - {d['technique']['name']} ({d['technique']['tactic']})")
        st.write("**Preuves utilisées**"); st.table({"preuve": list(d["evidence"]), "valeur": [str(v) for v in d["evidence"].values()]})
        st.write(f"**Justification** : {d['reasoning']}")
        for f in d["flags"]:
            st.warning(f"Garde-fou déclenché : {f}")
        st.write(f"**Action proposée** : `{d['recommended_action']}`")
        if d["requires_human"]:
            ok = st.button("✅ Approuver et exécuter (simulé)")
            if ok:
                st.success(execute(d, approved_by_human=True))
        else:
            st.info(execute(d))
    with st.expander("Rapport (copiable)"):
        st.markdown(d["report"])
