import pandas as pd

from model import detect_insider_threats


def score_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    UEBA service layer.

    Takes telemetry dataframe,
    processes threat detection,
    returns scored dataframe.
    """

    return detect_insider_threats(df)