import streamlit as st
from pymongo import MongoClient
import pandas as pd
import plotly.express as px

# Koneksi ke MongoDB
client = MongoClient('mongodb://localhost:27017/')  # Sesuaikan dengan URI MongoDB Anda
db = client['database']  # Ganti dengan nama database Anda
predictions_collection = db['predictions']  # Ganti dengan nama koleksi predictions Anda

# Fungsi untuk mengambil data dari MongoDB
def fetch_data():
    cursor = predictions_collection.find({})
    data = []
    for doc in cursor:
        doc.pop('_id', None)
        data.append(doc)
    return data

# Fungsi untuk memproses data
def process_data(data):
    df = pd.DataFrame(data)
    # Ubah kolom tanggal ke tipe datetime
    df['tanggal'] = pd.to_datetime(df['tanggal'], format='%d-%m-%Y')
    return df

def main():
    st.title('Data Hasil Deteksi')

    data = fetch_data()
    if data:
        df = process_data(data)

        # Tampilkan data sebagai tabel jika diinginkan
        if st.checkbox('Tampilkan Data'):
            st.table(df)

        # Grafik 1: Jumlah tiap kendaraan berdasarkan tempat (label dan location)
        st.header("Jumlah Tiap Kendaraan Berdasarkan Tempat")
        count_by_location = df.groupby(['location', 'label']).size().reset_index(name='counts')
        fig1 = px.bar(count_by_location, x='location', y='counts', color='label',
                      title="Jumlah Tiap Kendaraan Berdasarkan Tempat",
                      labels={'location': 'Tempat', 'counts': 'Jumlah', 'label': 'Kendaraan'})
        st.plotly_chart(fig1)

        # Grafik 2: Keramaian dari tiap kendaraan berdasarkan label dan location
        st.header("Keramaian dari Tiap Kendaraan Berdasarkan Tempat")
        fig2 = px.bar(count_by_location, x='location', y='counts', color='label', barmode='group',
                      title="Keramaian dari Tiap Kendaraan Berdasarkan Tempat",
                      labels={'location': 'Tempat', 'counts': 'Jumlah', 'label': 'Kendaraan'})
        st.plotly_chart(fig2)
    else:
        st.write("Tidak ada data yang tersedia.")

if __name__ == '__main__':
    main()
