export interface PendingTransaction {
  txHash: string;
  requestId: string;
  chainId: number;
  explorerDeserializationFormat: number;
  explorerDeserializationSchema: any;
  callbackSerializationFormat: number;
  callbackSerializationSchema: any;
  sender: string;
  path: string;
  fromAddress: string;
}

export interface ProcessedTransaction {
  unsignedTxHash: string;
  signedTxHash: string;
  signature: any;
  signedTransaction: string;
  fromAddress: string;
}

export interface TransactionOutput {
  success: boolean;
  output: any;
}
