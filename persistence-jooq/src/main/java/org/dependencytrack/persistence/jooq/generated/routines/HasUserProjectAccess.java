/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.routines;


import org.dependencytrack.persistence.jooq.generated.DefaultSchema;
import org.jooq.Field;
import org.jooq.Parameter;
import org.jooq.impl.AbstractRoutine;
import org.jooq.impl.DSL;
import org.jooq.impl.Internal;
import org.jooq.impl.SQLDataType;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class HasUserProjectAccess extends AbstractRoutine<Boolean> {

    private static final long serialVersionUID = 50899767;

    /**
     * The parameter <code>has_user_project_access.RETURN_VALUE</code>.
     */
    public static final Parameter<Boolean> RETURN_VALUE = Internal.createParameter("RETURN_VALUE", SQLDataType.BOOLEAN, false, false);

    /**
     * The parameter <code>has_user_project_access.project_id</code>.
     */
    public static final Parameter<Long> PROJECT_ID = Internal.createParameter("project_id", SQLDataType.BIGINT, false, false);

    /**
     * The parameter <code>has_user_project_access.user_id</code>.
     */
    public static final Parameter<Long> USER_ID = Internal.createParameter("user_id", SQLDataType.BIGINT, false, false);

    /**
     * Create a new routine call instance
     */
    public HasUserProjectAccess() {
        super("has_user_project_access", DefaultSchema.DEFAULT_SCHEMA, DSL.comment(""), SQLDataType.BOOLEAN);

        setReturnParameter(RETURN_VALUE);
        addInParameter(PROJECT_ID);
        addInParameter(USER_ID);
    }

    /**
     * Set the <code>project_id</code> parameter IN value to the routine
     */
    public void setProjectId(Long value) {
        setValue(PROJECT_ID, value);
    }

    /**
     * Set the <code>project_id</code> parameter to the function to be used with
     * a {@link org.jooq.Select} statement
     */
    public HasUserProjectAccess setProjectId(Field<Long> field) {
        setField(PROJECT_ID, field);
        return this;
    }

    /**
     * Set the <code>user_id</code> parameter IN value to the routine
     */
    public void setUserId(Long value) {
        setValue(USER_ID, value);
    }

    /**
     * Set the <code>user_id</code> parameter to the function to be used with a
     * {@link org.jooq.Select} statement
     */
    public HasUserProjectAccess setUserId(Field<Long> field) {
        setField(USER_ID, field);
        return this;
    }
}
