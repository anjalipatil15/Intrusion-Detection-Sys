import streamlit as st
import pandas as pd
import time

st.title("Intrusion Detection System Dashboard")

LOG_FILE = "traffic_log.csv"

while True:

    try:
        df = pd.read_csv(LOG_FILE, header=None, on_bad_lines="skip")

        clean_rows = []

        for row in df.values:

            if len(row) == 3:
                # old format
                src, dst, attack = row
                clean_rows.append([None, src, dst, attack])

            elif len(row) >= 4:
                # new format
                ts, src, dst, attack = row[:4]
                clean_rows.append([ts, src, dst, attack])

        clean_df = pd.DataFrame(
            clean_rows,
            columns=["timestamp","src_ip","dst_ip","attack"]
        )

        st.metric("Total Alerts", len(clean_df))

        st.subheader("Recent Traffic")
        st.dataframe(clean_df.tail(50))

        st.subheader("Attack Distribution")
        st.bar_chart(clean_df["attack"].value_counts())

    except Exception as e:
        st.write("Waiting for logs...")

    time.sleep(2)
    st.rerun()