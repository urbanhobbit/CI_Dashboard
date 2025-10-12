import streamlit as st
import pandas as pd
import plotly.express as px
import bcrypt

st.set_page_config(
    page_title="Çocuk İhtiyacı Araştırması Paneli",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Arayüz stilini CSS ile doğrudan ayarla
st.markdown("""
<style>
    .main { background-color: #F0F2F6; }
    body { color: #31333F; }
</style>
""", unsafe_allow_html=True)


# --- ŞİFRE KONTROL FONKSİYONU ---
def check_password():
    try:
        hashed_passwords_list = st.secrets["credentials"]["passwords"]
    except (FileNotFoundError, KeyError):
        st.error("Uygulama için şifre yapılandırması (secrets.toml) bulunamadı.")
        return False

    password = st.sidebar.text_input("Şifre:", type="password", key="password_input")

    if not password:
        st.sidebar.warning("Lütfen erişim için şifrenizi girin.")
        st.stop()

    is_authenticated = False
    for hashed_password in hashed_passwords_list:
        try:
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                is_authenticated = True
                break
        except Exception:
            continue 

    if not is_authenticated:
        st.sidebar.error("Girilen şifre yanlış.")
        st.stop()

    st.sidebar.success("Giriş başarılı!")
    st.sidebar.markdown("---")
    return True

# --- ANA UYGULAMA KODU ---
if 'authentication_status' not in st.session_state:
    st.session_state['authentication_status'] = False

if not st.session_state['authentication_status']:
    if check_password():
        st.session_state['authentication_status'] = True
        # DÜZELTME: st.experimental_rerun() yerine st.rerun() kullanıldı.
        st.rerun() 
else:
    AKTIF_PALET = ['#E3120B', '#004165', '#8C8C8C', '#50A6C2', '#333333']

    DATA_FILES = {
        "Çocuk Verileri": "Bilesik_Cocuk v04.xlsx",
        "Ebeveyn Verileri": "Bilesik_Ebeveyn v03.xlsx"
    }

    CHILD_SHEET_CONFIG = {
        "Cinsiyete Göre": {"sheet_name": "Cinsiyet"},
        "Okul Türüne Göre (Devlet/Özel)": {"sheet_name": "Devlet-Özel Okul (a04)"},
        "Yaş Grubuna Göre": {"sheet_name": "yasgrup"},
        "Cinsiyet ve Yaş Grubuna Göre": {"sheet_name": "Cinsxyaş"},
        "Yaşanılan Şehire Göre": {"sheet_name": "ilREC"},
        "Sosyoekonomik Statüye Göre (SES)": {"sheet_name": "SES1RC(ağırlıklı)"}
    }

    PARENT_SHEET_CONFIG = {
        "Cinsiyete Göre": {"sheet_name": "Cinsiyet"},
        "Çocuk Sayısına Göre": {"sheet_name": "Çocuk sayısı"},
        "Yaşanılan Şehire Göre": {"sheet_name": "İlREC"},
        "Sosyoekonomik Statüye Göre (SES)": {"sheet_name": "SES1REC"}
    }

    DATASET_CONFIGS = {
        "Çocuk Verileri": CHILD_SHEET_CONFIG,
        "Ebeveyn Verileri": PARENT_SHEET_CONFIG
    }

    @st.cache_data
    def load_and_process_data(file_path, sheet_name):
        try:
            df = pd.read_excel(file_path, sheet_name=sheet_name, header=0)
            df.columns = [str(col).strip() for col in df.columns]
            if 'Total' in df.columns:
                df.rename(columns={'Total': 'Genel'}, inplace=True)
            df.rename(columns={df.columns[0]: 'Domain', df.columns[1]: 'Soru/Alt Kategori'}, inplace=True)
            
            static_cols = ['Domain', 'Soru/Alt Kategori', 'Genel']
            value_vars = [col for col in df.columns if col not in static_cols]

            if not value_vars:
                return None, None

            df.dropna(subset=['Soru/Alt Kategori'], inplace=True)
            df = df[df['Soru/Alt Kategori'].astype(str).str.strip() != '']
            
            df['Domain'] = df['Domain'].ffill()
            df['Soru/Alt Kategori'] = df['Soru/Alt Kategori'].astype(str).str.replace(r'.* - ', '', regex=True)
            
            cols_to_process = value_vars + ['Genel']
            for col in cols_to_process:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')

            df = df[~df['Soru/Alt Kategori'].str.contains("Total %, N", na=False)]
            
            return df, value_vars
        except Exception as e:
            st.error(f"Veri yüklenirken bir hata oluştu: {e}. Lütfen dosya adlarını ve sayfa adlarını kontrol edin.")
            return None, None

    def get_dynamic_summary(df, value_vars):
        try:
            df_copy = df.copy()
            df_copy['fark'] = df_copy[value_vars].max(axis=1) - df_copy[value_vars].min(axis=1)
            max_diff_row = df_copy.loc[df_copy['fark'].idxmax()]
            soru_text = max_diff_row['Soru/Alt Kategori']
            fark_value = max_diff_row['fark']
            return f"💡 **Öne Çıkan Bilgi:** Gruplar arasındaki en belirgin görüş ayrılığı **{fark_value:.1%}** puan ile '**{soru_text}**' sorusunda gözlemlenmiştir."
        except Exception:
            return "💡 Öne çıkan bilgi hesaplanamadı."

    st.title("📊 Çocuk İhtiyacı Araştırması Paneli")

    st.sidebar.title("Ayarlar")
    selected_dataset_name = st.sidebar.selectbox(
        "1. Veri Setini Seçin:",
        list(DATASET_CONFIGS.keys()),
        index=0
    )
    active_config = DATASET_CONFIGS[selected_dataset_name]
    st.sidebar.markdown("---")

    selected_analysis = st.sidebar.radio(
        "2. Analiz Türünü Seçin:",
        list(active_config.keys()),
        index=0
    )

    file_to_load = DATA_FILES[selected_dataset_name]
    analysis_details = active_config[selected_analysis]

    df, value_vars = load_and_process_data(file_to_load, analysis_details['sheet_name'])

    if df is not None and value_vars is not None:
        st.header(f"📈 {selected_analysis} ({selected_dataset_name})")
        
        domains = df['Domain'].unique()
        
        try:
            default_index = list(domains).index(st.session_state.get('selected_domain'))
        except (ValueError, TypeError):
            default_index = 0

        selected_domain = st.selectbox(
            "İncelemek istediğiniz ana kategoriyi (domain) seçin:", 
            domains,
            index=default_index,
            key=f"{selected_dataset_name}_{selected_analysis}"
        )
        st.session_state['selected_domain'] = selected_domain

        if selected_domain:
            domain_df = df[df['Domain'] == selected_domain].copy()

            st.markdown("#### **Genel Bakış**")
            col1, col2, col3 = st.columns(3)
            col1.metric("Toplam Soru Sayısı", f"{domain_df.shape[0]} adet")
            
            if not domain_df.empty and 'Genel' in domain_df.columns and not domain_df['Genel'].isnull().all():
                highest_item_row = domain_df.loc[domain_df['Genel'].idxmax()]
                col2.metric(
                    "En Yüksek Oranlı Soru (Genel)", 
                    f"{str(highest_item_row['Soru/Alt Kategori'])[:30]}...",
                    f"{highest_item_row['Genel']:.1%}"
                )
                lowest_item_row = domain_df.loc[domain_df['Genel'].idxmin()]
                col3.metric(
                    "En Düşük Oranlı Soru (Genel)",
                    f"{str(lowest_item_row['Soru/Alt Kategori'])[:30]}...",
                    f"{lowest_item_row['Genel']:.1%}",
                    delta_color="inverse"
                )
            
            st.markdown("---")

            summary_text = get_dynamic_summary(domain_df, value_vars)
            st.info(summary_text)

            melted_df = pd.melt(
                domain_df, id_vars=['Soru/Alt Kategori'], value_vars=value_vars,
                var_name='Grup', value_name='Yüzde'
            )
            
            fig = px.bar(
                melted_df, x='Yüzde', y='Soru/Alt Kategori', color='Grup',
                orientation='h', barmode='group',
                color_discrete_sequence=AKTIF_PALET,
                height=max(600, len(domain_df) * 35),
                labels={'Yüzde': 'Yüzde (%)', 'Soru/Alt Kategori': ''},
                title=f"'{selected_domain}' Kategorisi İçin Karşılaştırmalı Dağılım",
                text=melted_df['Yüzde'].apply(lambda x: f'{x:.1%}' if pd.notna(x) else '')
            )
            fig.update_layout(
                xaxis_title="Yüzde (%)", yaxis_title="",
                legend_title_text='Kırılım', xaxis_tickformat='.0%',
                yaxis={'categoryorder':'total ascending'}
            )
            fig.update_traces(textposition='outside', hovertemplate='%{y}<br><b>%{x:.1%}</b>')
            st.plotly_chart(fig, use_container_width=True)

            with st.expander("📂 Filtrelenmiş Veri Detaylarını Görüntüle / İndir"):
                display_cols = ['Soru/Alt Kategori'] + value_vars + ['Genel']
                st.dataframe(
                    domain_df[display_cols].style.format(
                        {col: '{:.2%}' for col in value_vars + ['Genel']}
                    )
                )
                
                csv = domain_df[display_cols].to_csv(index=False).encode('utf-8-sig')
                st.download_button(
                    label="⬇️ Veriyi CSV Olarak İndir",
                    data=csv,
                    file_name=f'{selected_dataset_name}_{selected_analysis}_{selected_domain}.csv',
                    mime='text/csv',
                )
    else:
        st.error("Veri yüklenemedi. Lütfen dosya adlarının, sayfa adlarının ve klasör yapısının doğru olduğundan emin olun.")