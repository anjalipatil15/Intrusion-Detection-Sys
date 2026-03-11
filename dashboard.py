import streamlit as st
import pandas as pd
import time

st.title("Real-Time Intrusion Detection System")

st.subheader("Live Network Traffic Monitoring")

st.write("This dashboard displays real-time network traffic data and attack detections. It updates every 2 seconds to reflect the latest captured packets and their classifications.")

placeholder = st.empty()
while True:
    try:
        data = pd.read_csv("traffic_log.csv",
                           names=["Source IP","Destination IP","Attack"])

        with placeholder.container():

            st.metric("Total Packets", len(data))

            st.subheader("Attack Distribution")

            st.bar_chart(data["Attack"].value_counts())

            st.subheader("Recent Traffic")

            st.dataframe(data.tail(10))

    except:
        st.write("Waiting for traffic data...")

    time.sleep(2)