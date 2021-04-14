export enum CVSS_METRIC {
  AV,
  AC,
  PR,
  UI,
  TC,
  C,
  I,
  A,
}

export interface CvssScoreMatrix {
  name: string;
  max: number;
  scores: number[];
}

export enum AV {
  N = 0,
  A = 1,
  L = 2,
  P = 3,
}

export enum AC {
  L = 0,
  M = 1,
  H = 2,
}

export enum PR {
  N = 0,
  L = 1,
  H = 2,
}

export enum UI {
  N = 0,
  R = 1,
}

export enum TC {
  L = 0,
  M = 1,
  H = 2,
  E = 3,
}

export const cvssMatrices: CvssScoreMatrix[] = [
  { name: "Attack Vector", max: 3, scores: [0.85, 0.62, 0.55, 0.2] },
  { name: "Access Complexity", max: 2, scores: [0.77, 0.62, 0.44] },
  { name: "Privilege Required", max: 2, scores: [0.85, 0.62, 0.27] },
  { name: "User Interaction", max: 1, scores: [0.85, 0.62] },
  { name: "Time Complexity", max: 3, scores: [0.85, 0.62, 0.2, 0.1] },
];

export const calculateCvssBaseMtrics = (metricValues: number[]) => {
  let tempVal = 0;
  // get attack vector
  tempVal =
    metricValues[CVSS_METRIC.AV] > cvssMatrices[CVSS_METRIC.AV].max
      ? cvssMatrices[CVSS_METRIC.AV].max
      : metricValues[CVSS_METRIC.AV];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const avValue = cvssMatrices[CVSS_METRIC.AV].scores[tempVal];

  // get access complexity
  tempVal =
    metricValues[CVSS_METRIC.AC] > cvssMatrices[CVSS_METRIC.AC].max
      ? cvssMatrices[CVSS_METRIC.AC].max
      : metricValues[CVSS_METRIC.AC];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const acValue = cvssMatrices[CVSS_METRIC.AC].scores[tempVal];

  // get previlege required
  tempVal =
    metricValues[CVSS_METRIC.PR] > cvssMatrices[CVSS_METRIC.PR].max
      ? cvssMatrices[CVSS_METRIC.PR].max
      : metricValues[CVSS_METRIC.PR];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const prValue = cvssMatrices[CVSS_METRIC.PR].scores[tempVal];

  // get user interaction
  tempVal =
    metricValues[CVSS_METRIC.UI] > cvssMatrices[CVSS_METRIC.UI].max
      ? cvssMatrices[CVSS_METRIC.UI].max
      : metricValues[CVSS_METRIC.UI];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const uiValue = cvssMatrices[CVSS_METRIC.UI].scores[tempVal];

  // get time complexity
  tempVal =
    metricValues[CVSS_METRIC.TC] > cvssMatrices[CVSS_METRIC.TC].max
      ? cvssMatrices[CVSS_METRIC.TC].max
      : metricValues[CVSS_METRIC.TC];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const tcValue = cvssMatrices[CVSS_METRIC.TC].scores[tempVal];

  const result = 2.49 * avValue * acValue * prValue * uiValue * tcValue;
  return result;
};