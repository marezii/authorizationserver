package com.nistruct.authorizationserver.dao;

import com.nistruct.authorizationserver.model.JwkExposedModel;
import org.springframework.data.repository.CrudRepository;

public interface JwkExposedModelRepository extends CrudRepository<JwkExposedModel, String> {
}
