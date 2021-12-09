# Ciência de Dados
> Trabalho Prático | CIC-Darknet2020 dataset

Link: https://www.unb.ca/cic/datasets/darknet2020.html

Arquivo usado: Darknet.csv

**Objetivo:** Detectar o tráfego darknet, combinando a categorização de dois conjuntos de dados públicos, em tráfego Tor, Non-Tor e VPN, Non-VPN.

<details><summary>Colunas: 85</summary>

- Flow ID	
- Src IP	
- Src Port
- Dst IP	
- Dst Port	
- Protocol	
- Timestamp	
- Flow Duration	
- Total Fwd Packet	
- Total Bwd packets	
- Total Length of Fwd Packet	
- Total Length of Bwd Packet	
- Fwd Packet Length Max	
- Fwd Packet Length Min	
- Fwd Packet Length Mean	
- Fwd Packet Length Std	
- Bwd Packet Length Max	
- Bwd Packet Length Min	
- Bwd Packet Length Mean	
- Bwd Packet Length Std	
- Flow Bytes/s	
- Flow Packets/s	
- Flow IAT Mean	
- Flow IAT Std	
- Flow IAT Max	
- Flow IAT Min
- Fwd IAT Total 
- Fwd IAT Mean	
- Fwd IAT Std	
- Fwd IAT Max	
- Fwd IAT Min	
- Bwd IAT Total	
- Bwd IAT Mean	
- Bwd IAT Std	
- Bwd IAT Max	
- Bwd IAT Min	
- Fwd PSH Flags	
- Bwd PSH Flags	
- Fwd URG Flags	
- Bwd URG Flags	
- Fwd Header Length	
- Bwd Header Length	
- Fwd Packets/s	
- Bwd Packets/s	
- Packet Length Min	
- Packet Length Max	
- Packet Length Mean	
- Packet Length Std	
- Packet Length Variance	
- FIN Flag Count	
- SYN Flag Count	
- RST Flag Count	
- PSH Flag Count	
- ACK Flag Count	
- URG Flag Count	
- CWE Flag Count	
- ECE Flag Count	
- Down/Up Ratio	
- Average Packet Size	
- Fwd Segment Size Avg	
- Bwd Segment Size Avg	
- Fwd Bytes/Bulk Avg	
- Fwd Packet/Bulk Avg	
- Fwd Bulk Rate Avg	
- Bwd Bytes/Bulk Avg	
- Bwd Packet/Bulk Avg	
- Bwd Bulk Rate Avg	
- Subflow Fwd Packets	
- Subflow Fwd Bytes	
- Subflow Bwd Packets	
- Subflow Bwd Bytes	
- FWD Init Win Bytes	
- Bwd Init Win Bytes	
- Fwd Act Data Pkts	
- Fwd Seg Size Min
- Active Mean	
- Active Std	
- Active Max	
- Active Min	
- Idle Mean	
- Idle Std	
- Idle Max	
- Idle Min	
- Label	
- Label


Legendas:
- Flow IAT: Flow Inter Arrival Time, the time between two packets sent in either direction
- Fwd IAT: Forward Inter Arrival Time, the time between two packets sent forward direction
- Bwd IAT: Backward Inter Arrival Time, the time bettween two packets sent backwards
- Active: The amount of time time a flow was active before going idle
- Idle: The amount of time time a flow was idle before becoming active
</details>

---

**Referência:** Arash Habibi Lashkari, Gurdip Kaur, and Abir Rahali, “DIDarknet: A Contemporary Approach to Detect and Characterize the Darknet Traffic using Deep Image Learning”, 10th International Conference on Communication and Network Security, Tokyo, Japan, November 2020.

## Exploração de Dados

<a href="https://colab.research.google.com/github/jacksonrossi/ciencia-dados-darknet/blob/main/exploracao.ipynb" target="_blank"><img alt="Colab - Exploração de Dados" src="https://img.shields.io/badge/Open%20in%20Colab-grey?logo=google-colab" /></a>

Pontos observados na exploração:
- Dados majoritariamente numéricos. Das 85 colunas, 6 são strings: `flow_id`, `src_ip`, `dst_ip`, `timestamp`, `label` e `label.1`.
- O dataset é mal distribuido na categoria Tor e Non-Tor

|       | frequência  |porcentagem|
|---|---|---|
|nonTOR |      59784  |   0.659516|
|TOR    |       8044  |   0.009839|
|nonVPN |      23861  |   0.168652|
|VPN    |      22919  |   0.161993|


- As colunas de IP (origem e destino) são atributos textuais e acredito que não faça sentido transformá-los em números. O que é possível fazer é substituir essas colunas por um indicativo de endereço ip privado, mas não acho que seja muito produtivo.

Então, por enquanto:

- **Mantém**

       'bwd_packet_length_mean',
      'bwd_packet_length_std',
      'bwd_packet_length_min',
      'bwd_packet_length_max',
      'fwd_packet_length_mean',
      'fwd_packet_length_std',
      'fwd_packet_length_min',
      'fwd_packet_length_max',
      'bwd_iat_max',
      'bwd_iat_total',
      'fwd_iat_mean',
      'fwd_iat_std',
      'fwd_iat_max',
      'fwd_iat_total',
      'fwd_psh_flags',
      'bwd_header_length',
      'fwd_header_length',
      'bwd_segment_size_avg',
      'fwd_segment_size_avg',
      'bwd_packet/bulk_avg',
      'bwd_init_win_bytes',
      'fwd_init_win_bytes',
      'fwd_act_data_pkts',
      'idle_mean',
      'idle_min',
      'idle_max',
      'packet_length_mean',
      'packet_length_std',
      'packet_length_min',
      'packet_length_max',
      'flow_duration',
      'flow_iat_mean',
      'flow_iat_std',
      'flow_iat_max',
      'subflow_fwd_packets',
      'subflow_fwd_bytes',
      'subflow_bwd_bytes',
      'total_fwd_packet',
      'total_bwd_packets',
      'protocol',
      'fin_flag_count',
      'syn_flag_count',
      'psh_flag_count',
      'ack_flag_count',
      'average_packet_size',
      'label'
- **Retira**

      'bwd_iat_mean',
      'bwd_iat_std',
      'bwd_iat_min',
      'fwd_iat_min',
      'bwd_psh_flags',
      'bwd_urg_flags',
      'fwd_urg_flags',
      'bwd_packets/s',
      'fwd_packets/s',
      'bwd_bytes/bulk_avg',
      'fwd_bytes/bulk_avg',
      'fwd_packet/bulk_avg',
      'bwd_bulk_rate_avg',
      'fwd_bulk_rate_avg',
      'fwd_seg_size_min',
      'active_mean',
      'active_std',
      'active_min',
      'active_max',
      'idle_std',
      'packet_length_variance',
      'flow_id',
      'flow_bytes/s',
      'flow_packets/s',
      'flow_iat_min',
      'subflow_bwd_packets',
      'total_length_of_fwd_packet',
      'total_length_of_bwd_packet',
      'src_ip',
      'src_port',
      'dst_ip',
      'dst_port',
      'timestamp',
      'rst_flag_count',
      'urg_flag_count',
      'cwe_flag_count',
      'ece_flag_count',
      'down/up_ratio',
      'label.1'

## Extração de Características

<a href="https://colab.research.google.com/github/jacksonrossi/ciencia-dados-darknet/blob/main/extracao_caracteristicas.ipynb" target="_blank"><img alt="Colab - Extração de Características" src="https://img.shields.io/badge/Open%20in%20Colab-grey?logo=google-colab" /></a>

A partir das colunas selecionadas no precesso de exploração, analisei a correlação entre as variáveis. Com isso pude perceber que existiam atributos correlacionados e que poderiam ser ignorados. São eles:

'ack_flag_count', 'average_packet_size',
'bwd_iat_total', 'bwd_packet/bulk_avg',
'bwd_packet_length_max', 'bwd_segment_size_avg',
'flow_duration', 'flow_iat_max',
'flow_iat_mean', 'flow_iat_std',
'fwd_header_length', 'fwd_iat_max',
'fwd_packet_length_max', 'fwd_segment_size_avg',
'idle_max', 'idle_min',
'packet_length_min', 'packet_length_std',
'subflow_bwd_bytes', 'subflow_fwd_bytes',
'total_bwd_packets'

Desta forma, as colunas que vão ser usadas no processo de machine learning são:

       'bwd_packet_length_mean', 'bwd_packet_length_std',
       'bwd_packet_length_min', 'fwd_packet_length_mean',
       'fwd_packet_length_std', 'fwd_packet_length_min', 'bwd_iat_max',
       'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_total', 'fwd_psh_flags',
       'bwd_header_length', 'bwd_init_win_bytes', 'fwd_init_win_bytes',
       'fwd_act_data_pkts', 'idle_mean', 'packet_length_mean',
       'packet_length_max', 'subflow_fwd_packets', 'total_fwd_packet',
       'protocol', 'fin_flag_count', 'syn_flag_count', 'psh_flag_count',
       'label'

## Machine Learning

<a href="https://colab.research.google.com/github/jacksonrossi/ciencia-dados-darknet/blob/main/projeto_final.ipynb" target="_blank"><img alt="Colab - Extração de Características" src="https://img.shields.io/badge/Open%20in%20Colab-grey?logo=google-colab" /></a>

A partir da [especificação](especificacao.md) do projeto final, foram feitos treinamento e testes com 3 modelos diferentes de machine learning: KNN, Random Forest e SVM.

Poucos parâmetros foram alterados em cada modelo, dado que algumas alterações não faziam diferença. No SVM, devido a proporção de classes estar desbalanceada, foi preciso ajustar o `class_weight`. O `probability` é devido ao dataset ser multiclass. Já o `max_iter` foi definido para possibilitar a execução, pois numa primeira tentativa a execução passou de 1h e não terminou.

Osb: As primeiras execuções de treinamento mostraram que a predição pode ser demorada. Suponho que seja por conta de ser uma classifição multiclasse e não binária.

Assim, para tentar melhorar um pouco o tempo de espera, as execuções são paralelas

### Conclusões

De modo geral, o Random Forest parece a melhor solução para classificar o tráfego:

- Tem a melhor precisão
- Menor erro
- Menor tempo de predição

O SVM teve um desempenho baixíssimo, já que seu tempo de treino foi muito grande e precisou de limitação de iterações. O fato do dataset ser multiclasse pode ser um agravante no tempo de treino, além do tamanho do dataset. Então o SVM não é viável de forma alguma para esses dados.

Já o KNN teve um tempo de treino melhor que o Random Forest. No entanto, a penalidade acontece no tempo de predição, que é muito maior ao Random Forest.

Assim, o Random Forest é o melhor algoritmo de machine learning entre os três estudados.

