# IdentityLens ML models package.
# Makes `models` a regular (non-namespace) package so that imports such as
#   from models.isolation_forest import MLModel
# resolve deterministically on all runtimes, including Streamlit Cloud
# (Python 3.14 / Linux) where PEP 420 namespace-package resolution is unreliable.
