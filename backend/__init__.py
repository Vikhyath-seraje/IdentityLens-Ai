# IdentityLens backend package.
# Makes `backend` a regular (non-namespace) package so that imports such as
#   from backend.anomaly_detection import MITRE_MAPPING, get_mitre_mapping
# resolve deterministically on all runtimes, including Streamlit Cloud
# (Python 3.14 / Linux) where PEP 420 namespace-package resolution is unreliable.
